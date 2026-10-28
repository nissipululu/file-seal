// Attack tests for the seal tool. Run: dotnet run --project SonsetSeal.Tests [-c Release] [-- --with-store]
// A test passes only when the checker gives the verdict a careful person would want.
// Everything runs in a temporary folder. By default nothing touches the computer's own key store (the Mac Keychain, the Windows
// certificate store); add --with-store to also run the tests that make a department key there. They remove it again.
using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using SonsetSeal;

var skipStore = !args.Contains("--with-store");
var results = new List<(string Name, bool Ok)>();
var started = Stopwatch.StartNew();

void Expect(string name, bool ok, string detail = "")
{
    results.Add((name, ok));
    Console.WriteLine($"{(ok ? "PASS" : "FAIL")}  {name}{(ok || detail.Length == 0 ? "" : "   <-- " + detail)}");
}

var tempRoot = Path.Combine(Environment.GetEnvironmentVariable("SEAL_TEST_TMP") ?? Path.GetTempPath(), "sonsetseal-tests-" + Guid.NewGuid().ToString("N")[..8]);
Directory.CreateDirectory(tempRoot);
var now = Time.Now();
// Nothing in this run may show a message on the screen, look at the real Downloads folder, or write to the real login items folder.
Environment.SetEnvironmentVariable("SONSETSEAL_NOTIFY", "off");
Environment.SetEnvironmentVariable("SONSETSEAL_DOWNLOADS", Path.Combine(tempRoot, "Downloads (test)"));
Boxes.LoginItemsFolderOverride = Path.Combine(tempRoot, "login items (test)");

// ----------------------------------------------------------------------------- helpers
(int Code, string Out, string Err) Cli(params string[] a)
{
    var o = new StringWriter();
    var e = new StringWriter();
    var code = CliApp.Run(a, o, e);
    return (code, o.ToString(), e.ToString());
}

string Verdict(string file, string trustFolder, DateTimeOffset? at = null)
{
    var t = at ?? now;
    return Checker.Check(file, TrustPolicy.FromFolder(trustFolder, t), t).Status;
}

CheckResult Full(string file, string trustFolder, DateTimeOffset? at = null)
{
    var t = at ?? now;
    return Checker.Check(file, TrustPolicy.FromFolder(trustFolder, t), t);
}

void Verdicts(string name, string file, string trustFolder, string want, DateTimeOffset? at = null)
{
    string got;
    try { got = Verdict(file, trustFolder, at); } catch (Exception e) { got = $"threw {e.GetType().Name}: {e.Message}"; }
    Expect(name, got == want, $"wanted {want}, got {got}");
}

bool Throws<T>(Action a, string? contains = null) where T : Exception
{
    try { a(); return false; }
    catch (T e) { return contains == null || e.Message.Contains(contains, StringComparison.OrdinalIgnoreCase); }
}

JsonObject ReadEnvelope(string path, out byte[] body)
{
    var t = SealFormat.ReadTrailer(path)!;
    body = File.ReadAllBytes(path)[..(int)t.BodyLength];
    return (JsonObject)JsonNode.Parse(t.Payload)!;
}

void WriteWith(string path, byte[] body, JsonObject env) =>
    File.WriteAllBytes(path, [.. body, .. SealFormat.BuildTrailer(Encoding.ASCII.GetBytes(env.ToJsonString()))]);

void WriteRaw(string path, byte[] body, byte[] payload, ulong? length = null, byte[]? magic = null)
{
    var len = new byte[8];
    System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian(len, length ?? (ulong)payload.Length);
    File.WriteAllBytes(path, [.. body, .. payload, .. len, .. (magic ?? SealFormat.Magic)]);
}

JsonObject Clone(JsonObject o) => (JsonObject)JsonNode.Parse(o.ToJsonString())!;

Dictionary<string, string> Fields3(string what = "Listing photo, 12 Example St") => new()
{
    ["Made by"] = "J. Smith, photographer", ["Made for"] = "Leasing team", ["What it is"] = what,
    ["Edits"] = "Colour and brightness only", ["Rights"] = "Owned by Example Property Group", ["Contact"] = "listings@example.com", ["Reference"] = "LST 2041"
};

// A company: its own authority, and departments that make their own keys and send only requests.
SigningIdentity MakeDepartment(Home home, string name, int days = 365)
{
    Department.Request(home, name, true, now);
    var csr = File.ReadAllBytes(Path.Combine(home.Departments, Names.Slug(name), "request.csr.pem"));
    var certPath = Authority.SignRequest(home, csr, name, days, now);
    Department.Install(home, name, File.ReadAllBytes(certPath));
    return Department.Load(home, name);
}

Home NewCompany(string folder, string company = "Example Property Group", string dept = "IT Department", int listDays = 30)
{
    var home = new Home(Path.Combine(tempRoot, folder));
    Authority.Init(home, company, dept, 10, listDays, now);
    return home;
}

string Seal(string src, SigningIdentity id, string? outPath = null, DateTimeOffset? at = null, Dictionary<string, string>? fields = null, bool replace = false) =>
    Sealer.Seal(src, id, fields ?? Fields3(), outPath ?? Path.Combine(Path.GetDirectoryName(src)!, Path.GetFileNameWithoutExtension(src) + ".out" + Guid.NewGuid().ToString("N")[..6] + Path.GetExtension(src)), replace, false, at);

// ---------------------------------------------------------------------------- the company
var home = NewCompany("company");
var marketing = MakeDepartment(home, "Marketing Department");
var leasing = MakeDepartment(home, "Leasing Department");
var files = Path.Combine(tempRoot, "files");
Directory.CreateDirectory(files);
var doc = Path.Combine(files, "report.pdf");
File.WriteAllBytes(doc, [.. "%PDF-1.4 pretend report "u8.ToArray(), .. RandomNumberGenerator.GetBytes(2000)]);
var other = Path.Combine(files, "other.bin");
File.WriteAllBytes(other, RandomNumberGenerator.GetBytes(3000));
var trust = home.Trust;

Console.WriteLine($"Working in {tempRoot}\n");

// 1 to 9: the basics and the cheats
var good = Seal(doc, marketing);
var r1 = Full(good, trust);
Expect("1  genuine sealed file passes", r1.Ok, r1.Reason);
Expect("1b names and fields read back in the fixed order",
    r1.Details is { } d && d.Signer == "Marketing Department" && d.Organisation == "Example Property Group" && d.IssuedBy == "IT Department"
    && d.IssuerOrganisation == "Example Property Group" && d.Claims.Select(c => c.Key).SequenceEqual(Fields.All) && d.Claims[0].Value == "J. Smith, photographer");
Expect("1c the original bytes sit untouched at the front", File.ReadAllBytes(good).AsSpan(0, (int)new FileInfo(doc).Length).SequenceEqual(File.ReadAllBytes(doc)));
Expect("1d the screen text names who issued it", Checker.Render(r1, false).Contains("Issued by     IT Department, Example Property Group"));
Verdicts("2  file with no seal is refused", doc, trust, "NO_SEAL");

var bytes = File.ReadAllBytes(good);
bytes[100] ^= 1;
var t3 = Path.Combine(files, "t3.pdf"); File.WriteAllBytes(t3, bytes);
Verdicts("3  one flipped bit is caught", t3, trust, "CHANGED");
var t4 = Path.Combine(files, "t4.pdf"); File.WriteAllBytes(t4, [.. File.ReadAllBytes(good), 0x78]);
Verdicts("4  a byte added after the seal means no seal", t4, trust, "NO_SEAL");
var t5 = Path.Combine(files, "t5.pdf"); File.WriteAllBytes(t5, File.ReadAllBytes(good)[..^1]);
Verdicts("5  a byte cut off the end means no seal", t5, trust, "NO_SEAL");

var env = ReadEnvelope(good, out var body);
var t6 = Path.Combine(files, "t6.pdf"); WriteWith(t6, body[..^1], env);
Verdicts("6  one byte removed from the content is caught", t6, trust, "CHANGED");
var t6b = Path.Combine(files, "t6b.pdf"); WriteWith(t6b, [.. body, 0x78], env);
Verdicts("6b one byte added to the content is caught", t6b, trust, "CHANGED");

var e7 = Clone(env); e7["signed"]!["claims"]!["Rights"] = "Free for anyone";
var t7 = Path.Combine(files, "t7.pdf"); WriteWith(t7, body, e7);
Verdicts("7  editing the sealed information is caught", t7, trust, "SEAL_BROKEN");

var leasingSealed = Seal(other, leasing);
var envLeasing = ReadEnvelope(leasingSealed, out _);
var e8 = Clone(env); e8["cert"] = (string)envLeasing["cert"]!;
var t8 = Path.Combine(files, "t8.pdf"); WriteWith(t8, body, e8);
Verdicts("8  another department's certificate swapped in is caught", t8, trust, "SEAL_BROKEN");

var t9 = Path.Combine(files, "t9.pdf"); WriteWith(t9, File.ReadAllBytes(other), env);
Verdicts("9  a real seal moved onto a different file is caught", t9, trust, "CHANGED");

// 10 to 18: who is trusted
var impostor = NewCompany("impostor");
var impostorDept = MakeDepartment(impostor, "Marketing Department");
var fake = Seal(doc, impostorDept);
var rImpostor = Full(fake, trust);
Expect("10 impostor authority with the same names is refused", rImpostor.Status == "NOT_TRUSTED" && rImpostor.Reason.Contains("recognise"), rImpostor.Reason);

X509Certificate2 IssueRaw(Action<CertificateRequest> customise, AsymmetricAlgorithm key, string name = "Odd Signer")
{
    var (ca, caKey) = Authority.LoadCa(home);
    using var _ = ca; using var __ = caKey;
    CertificateRequest req = key is RSA r
        ? new(Names.Build(name, "Example Property Group"), r, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
        : new(Names.Build(name, "Example Property Group"), (ECDsa)key, HashAlgorithmName.SHA256);
    customise(req);
    var serial = RandomNumberGenerator.GetBytes(8); serial[0] = (byte)((serial[0] & 0x7F) | 0x40);
    return req.Create(ca.SubjectName, X509SignatureGenerator.CreateForECDsa(caKey), now.AddMinutes(-5), now.AddDays(100), serial);
}

using var tlsKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
using var tlsCert = IssueRaw(r => { r.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true)); r.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true)); r.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, true)); }, tlsKey);
Verdicts("11 a real certificate not meant for signing files is refused", Seal(doc, new KeyIdentity(tlsCert, tlsKey)), trust, "NOT_TRUSTED");

var (caCert, caKeyForLeaf) = Authority.LoadCa(home);
Verdicts("12 the authority's own certificate cannot sign files", Seal(doc, new KeyIdentity(caCert, caKeyForLeaf)), trust, "NOT_TRUSTED");

var wrongKey = Clone(env);
{
    var leasingId = leasing;
    var signedCanon = Canonical.Bytes((JsonObject)wrongKey["signed"]!.DeepClone());
    wrongKey["signature"] = Convert.ToBase64String(leasingId.Sign(signedCanon));
}
var t13 = Path.Combine(files, "t13.pdf"); WriteWith(t13, body, wrongKey);
Verdicts("13 a certificate signed for with someone else's key is caught", t13, trust, "SEAL_BROKEN");
using var strayKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
Expect("13b the sealer refuses a key that does not match its certificate", Throws<SealException>(() => Seal(doc, new KeyIdentity(marketing.Certificate, strayKey)), "does not match"));

Verdicts("14 sealed before the certificate existed is refused", Seal(doc, marketing, at: Time.ParseWhen("2020-01-01")), trust, "NOT_TRUSTED");
Verdicts("15 a seal dated in the future is refused", Seal(doc, marketing, at: now.AddDays(400)), trust, "NOT_TRUSTED");
var late = Seal(doc, marketing, at: now.AddDays(800));
var rLate = Full(late, trust, now.AddDays(801));
Expect("16 sealed after the certificate expired is refused", rLate.Status == "NOT_TRUSTED" && rLate.Reason.Contains("expired"), $"{rLate.Status}: {rLate.Reason}");

using var rsaKey = RSA.Create(2048);
using var rsaCert = IssueRaw(r => { r.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true)); r.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true)); r.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.4") }, true)); }, rsaKey, "Contracts Desk");
Verdicts("17 an RSA signer, like the ones a Windows company authority hands out, passes", Seal(doc, new KeyIdentity(rsaCert, rsaKey)), trust, "VERIFIED");
{
    var csr = new CertificateRequest("CN=Archive Desk", rsaKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1).CreateSigningRequest();
    var certFile = Authority.SignRequest(home, csr, "Archive Desk", 100, now);
    using var issued = X509Certificate2.CreateFromPem(File.ReadAllText(certFile));
    Verdicts("17b an RSA department request goes through the authority and its seals pass", Seal(doc, new KeyIdentity(issued, rsaKey)), trust, "VERIFIED");
}
using var weakRsa = RSA.Create(1024);
Expect("17c an RSA key shorter than 2048 bits is refused", Throws<SealException>(() => Authority.SignRequest(home, new CertificateRequest("CN=Weak", weakRsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1).CreateSigningRequest(), "Weak", 100, now), "shorter"));

// 18: a chain with a middle authority (the shape a larger company uses), trust folder built by hand
{
    using var rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    var rootReq = new CertificateRequest(Names.Build("Corporate Root", "Big Company"), rootKey, HashAlgorithmName.SHA256);
    rootReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 1, true));
    rootReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
    rootReq.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(rootReq.PublicKey, false));
    using var root = rootReq.CreateSelfSigned(now.AddDays(-1), now.AddYears(5));
    using var midKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    var midReq = new CertificateRequest(Names.Build("Issuing CA", "Big Company"), midKey, HashAlgorithmName.SHA256);
    midReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 0, true));
    midReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
    midReq.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(midReq.PublicKey, false));
    midReq.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(root, true, false));
    using var mid = midReq.Create(root, now.AddDays(-1), now.AddYears(3), [0x40, 1, 2, 3, 4, 5, 6, 7]);
    using var midWithKey = mid.CopyWithPrivateKey(midKey);
    using var leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    var leafReq = new CertificateRequest(Names.Build("Finance Department", "Big Company"), leafKey, HashAlgorithmName.SHA256);
    leafReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
    leafReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
    leafReq.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(mid, true, false));
    using var leaf = leafReq.Create(midWithKey, now.AddDays(-1), now.AddYears(1), [0x40, 9, 9, 9, 9, 9, 9, 9]);
    var bigTrust = Path.Combine(tempRoot, "big-trust"); Directory.CreateDirectory(bigTrust);
    File.WriteAllText(Path.Combine(bigTrust, "ca.pem"), root.ExportCertificatePem());
    File.WriteAllText(Path.Combine(bigTrust, "revoked.json"), RevocationList.Create(rootKey, Crypto.NormSerial(root.SerialNumber), now, 30, [], 1).ToJsonString());
    Verdicts("18 a signer under a middle authority passes when the seal carries the middle certificate", Seal(doc, new KeyIdentity(leaf, leafKey, [mid])), bigTrust, "VERIFIED");
    Verdicts("18b the same signer without the middle certificate is refused", Seal(doc, new KeyIdentity(leaf, leafKey)), bigTrust, "NOT_TRUSTED");
}

// 19 to 25: the withdrawn list
var rStale = Full(good, trust, now.AddDays(40));
Expect("19 an out of date withdrawn list means cannot confirm", rStale.Status == "CANNOT_CONFIRM" && rStale.Reason.Contains("ran out"), $"{rStale.Status}: {rStale.Reason}");
var noList = Path.Combine(tempRoot, "trust-nolist"); Directory.CreateDirectory(noList); File.Copy(Path.Combine(trust, "ca.pem"), Path.Combine(noList, "ca.pem"));
Verdicts("20 no withdrawn list at all means cannot confirm", good, noList, "CANNOT_CONFIRM");
var forged = Path.Combine(tempRoot, "trust-forged"); Directory.CreateDirectory(forged); File.Copy(Path.Combine(trust, "ca.pem"), Path.Combine(forged, "ca.pem"));
var forgedList = (JsonObject)JsonNode.Parse(File.ReadAllText(Path.Combine(trust, "revoked.json")))!; forgedList["next_update"] = "2040-01-01T00:00:00Z";
File.WriteAllText(Path.Combine(forged, "revoked.json"), forgedList.ToJsonString());
Verdicts("21 a withdrawn list edited by hand is refused", good, forged, "CANNOT_CONFIRM", now.AddDays(40));
var mixed = Path.Combine(tempRoot, "trust-mixed"); Directory.CreateDirectory(mixed); File.Copy(Path.Combine(trust, "ca.pem"), Path.Combine(mixed, "ca.pem")); File.Copy(Path.Combine(impostor.Trust, "revoked.json"), Path.Combine(mixed, "revoked.json"));
Verdicts("22 a withdrawn list signed by someone else is refused", good, mixed, "CANNOT_CONFIRM");
var junk = Path.Combine(tempRoot, "trust-junk"); Directory.CreateDirectory(junk); File.Copy(Path.Combine(trust, "ca.pem"), Path.Combine(junk, "ca.pem")); File.WriteAllText(Path.Combine(junk, "revoked.json"), "not json");
Verdicts("23 an unreadable withdrawn list means cannot confirm", good, junk, "CANNOT_CONFIRM");

{
    var longHome = NewCompany("long", listDays: 2000);
    var longDept = MakeDepartment(longHome, "Head Office");
    var old = Seal(doc, longDept);
    var rOld = Full(old, longHome.Trust, now.AddDays(400));
    Expect("24 certificate expired since, but valid when sealed, still passes with a note", rOld.Ok && rOld.Reason.Contains("expired since"), $"{rOld.Status}: {rOld.Reason}");
}

var beforeLeasing = Seal(other, leasing);
Verdicts("25 leasing file passes before withdrawal", beforeLeasing, trust, "VERIFIED");
Expect("25b withdrawing marketing works", Cli("authority", "revoke", "--home", home.Root, "--name", "Marketing Department", "--reason", "laptop lost").Code == 0);
var rRevoked = Full(good, trust);
Expect("25c a withdrawn signer's old file now fails with the reason", rRevoked.Status == "REVOKED" && rRevoked.Reason.Contains("laptop lost"), $"{rRevoked.Status}: {rRevoked.Reason}");
Verdicts("25d another department's file still passes", beforeLeasing, trust, "VERIFIED");
Verdicts("25e a withdrawn signer sealing again is still refused", Seal(other, marketing), trust, "REVOKED");
Expect("25f withdrawing twice is refused", Cli("authority", "revoke", "--home", home.Root, "--name", "Marketing Department").Code == 2);
Expect("25g the list shows who is withdrawn", Cli("authority", "list", "--home", home.Root).Out.Contains("WITHDRAWN"));
Expect("25h after publish the list is good for 30 more days", Authority.Publish(home, now, 30, null)["next_update"]!.ToString() == Time.Iso(now.AddDays(30)));

// 26 to 34: damaged seals
var payload = SealFormat.ReadTrailer(beforeLeasing)!.Payload;
var leasingBody = File.ReadAllBytes(beforeLeasing)[..(int)SealFormat.ReadTrailer(beforeLeasing)!.BodyLength];
var d1 = Path.Combine(files, "d1.bin"); WriteRaw(d1, leasingBody, payload, length: 1_000_000_000);
Verdicts("26 a length that does not fit the file is damaged", d1, trust, "DAMAGED");
var d2 = Path.Combine(files, "d2.bin"); WriteRaw(d2, leasingBody, []);
Verdicts("27 an empty seal is damaged", d2, trust, "DAMAGED");
var d3 = Path.Combine(files, "d3.bin"); WriteRaw(d3, leasingBody, "this is not json at all"u8.ToArray());
Verdicts("28 a seal that is not readable is damaged", d3, trust, "DAMAGED");
var envLeasing2 = ReadEnvelope(beforeLeasing, out _);
var e4 = Clone(envLeasing2); e4["cert"] = (string)envLeasing2["cert"]! + (string)env["cert"]!;
var d4 = Path.Combine(files, "d4.bin"); WriteWith(d4, leasingBody, e4);
Verdicts("29 two certificates in one place is damaged", d4, trust, "DAMAGED");
var e5 = Clone(envLeasing2); e5["signed"]!["claims"]!["Rights"] = 7;
var d5 = Path.Combine(files, "d5.bin"); WriteWith(d5, leasingBody, e5);
Verdicts("30 a field that is not text is damaged", d5, trust, "DAMAGED");
var e6 = Clone(envLeasing2); e6["signature"] = "!!!notbase64";
var d6 = Path.Combine(files, "d6.bin"); WriteWith(d6, leasingBody, e6);
Verdicts("31 a signature that is not readable is damaged", d6, trust, "DAMAGED");
var e7b = Clone(envLeasing2); e7b["signed"]!["file_size"] = true;
var d7 = Path.Combine(files, "d7.bin"); WriteWith(d7, leasingBody, e7b);
Verdicts("32 a wrong typed field is damaged", d7, trust, "DAMAGED");
var d8 = Path.Combine(files, "d8.bin"); WriteRaw(d8, "abc"u8.ToArray(), [], length: 999);
Verdicts("33 a marker that claims more seal than the file holds is damaged", d8, trust, "DAMAGED");
var d8b = Path.Combine(files, "d8b.bin"); File.WriteAllBytes(d8b, [.. "short"u8.ToArray(), .. SealFormat.Magic]);
Verdicts("33b a file too small to hold a seal is simply unsealed", d8b, trust, "NO_SEAL");
var d9 = Path.Combine(files, "d9.bin"); WriteRaw(d9, leasingBody, payload, magic: "~~SONSET-SEAL~2~"u8.ToArray());
Verdicts("34 an unknown seal version is no seal", d9, trust, "NO_SEAL");
var dupPayload = Encoding.ASCII.GetString(payload).Replace("\"v\":2", "\"v\":2,\"v\":2");
var d10 = Path.Combine(files, "d10.bin"); WriteRaw(d10, leasingBody, Encoding.ASCII.GetBytes(dupPayload));
Verdicts("34b a repeated field name is damaged", d10, trust, "DAMAGED");

// 35 to 46: how the tool behaves
Expect("35 a second authority will not overwrite the first", Throws<SealException>(() => Authority.Init(home, "Other", "Other IT", 10, 30, now), "already exists"));
Expect("36 a department made twice is refused", Throws<SealException>(() => Department.Request(home, "Leasing Department", true, now), "already set up"));
Expect("37 a second working certificate for the same name is refused", Throws<SealException>(() =>
{
    using var k = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    Authority.SignRequest(home, new CertificateRequest("CN=Leasing Department", k, HashAlgorithmName.SHA256).CreateSigningRequest(), "Leasing Department", 100, now);
}, "already has"));
Expect("38 a damaged request is refused", Throws<SealException>(() => Authority.SignRequest(home, "not a request"u8.ToArray(), "x", 100, now)));
{
    using var k = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    var csr = new CertificateRequest("CN=Tamper Desk", k, HashAlgorithmName.SHA256).CreateSigningRequest();
    csr[^3] ^= 0xFF;
    Expect("38b a request whose own signature fails is refused", Throws<SealException>(() => Authority.SignRequest(home, csr, "Tamper Desk", 100, now)));
}
Expect("39 sealing over the original is refused", Throws<SealException>(() => Sealer.Seal(other, leasing, Fields3(), other), "never overwrite"));
Expect("40 sealing a sealed file needs replace", Throws<SealException>(() => Sealer.Seal(beforeLeasing, leasing, Fields3(), Path.Combine(files, "x.bin")), "already carries"));
var resealed = Path.Combine(files, "resealed.bin");
Sealer.Seal(beforeLeasing, leasing, Fields3(), resealed, replace: true);
Expect("40b replace strips the old seal and the new one passes", Verdict(resealed, trust) == "VERIFIED" && File.ReadAllBytes(resealed).AsSpan(0, 3000).SequenceEqual(File.ReadAllBytes(other)));
foreach (var required in Fields.Required)
{
    var less = Fields3(); less.Remove(required);
    Expect($"41 sealing without '{required}' is refused", Throws<SealException>(() => Seal(other, leasing, fields: less), "required"));
}
Expect("41b a field that is not on the list is refused", Throws<SealException>(() => Seal(other, leasing, fields: new(Fields3()) { ["Approved for"] = "Public" }), "not a seal field"));
Expect("41c a field longer than 300 characters is refused", Throws<SealException>(() => Seal(other, leasing, fields: new(Fields3()) { ["Rights"] = new string('x', 301) }), "300"));
Expect("41d a missing file is refused", Throws<SealException>(() => Seal(Path.Combine(files, "nothing.bin"), leasing), "cannot find"));
var empty = Path.Combine(files, "empty.dat"); File.WriteAllBytes(empty, []);
Verdicts("42 an empty file can be sealed and checked", Seal(empty, leasing), trust, "VERIFIED");
var odd = Path.Combine(files, "Q3 résumé – final (1).txt"); File.WriteAllText(odd, "hi");
var oddFields = Fields3(); oddFields["Contact"] = "Zoë Ñandú, 日本語, 😀";
var rOdd = Full(Seal(odd, leasing, fields: oddFields), trust);
Expect("43 odd file names and non English text come back exactly", rOdd.Ok && rOdd.Details!.Claims.First(c => c.Key == "Contact").Value == "Zoë Ñandú, 日本語, 😀", rOdd.Reason);
var big = Path.Combine(files, "big.bin");
using (var fs = File.Create(big)) { var chunk = RandomNumberGenerator.GetBytes(1 << 20); for (var i = 0; i < 40; i++) fs.Write(chunk); }
var clock = Stopwatch.StartNew();
var bigSealed = Seal(big, leasing);
Verdicts("44 a 40 MB file seals and checks", bigSealed, trust, "VERIFIED");
Expect("44b in a few seconds", clock.Elapsed.TotalSeconds < 15, $"{clock.Elapsed.TotalSeconds:F1}s");
using (var fs = new FileStream(bigSealed, FileMode.Open, FileAccess.Write)) { fs.Seek(30L << 20, SeekOrigin.Begin); fs.Write([0xAA, 0xBB]); }
Verdicts("44c a change deep inside a big file is caught", bigSealed, trust, "CHANGED");

// installing the wrong certificate
{
    Department.Request(home, "Wrong Cert Desk", true, now);
    var wrong = File.ReadAllBytes(Directory.GetFiles(home.IssuedDir)[0]);
    Expect("45 installing a certificate made for a different key is refused", Throws<SealException>(() => Department.Install(home, "Wrong Cert Desk", wrong), "not made for"));
    Expect("45b a department with no certificate cannot seal", Throws<SealException>(() => Department.Load(home, "Wrong Cert Desk"), "no certificate yet"));
}

// the whole thing through the command line only
{
    var cliHome = Path.Combine(tempRoot, "cli-company");
    int Code(params string[] a) => Cli([.. a, "--home", cliHome]).Code;
    Expect("46 command line: authority init", Code("authority", "init", "--company", "Example Property Group", "--department", "IT Department") == 0);
    Expect("46b department request (key kept in a key file)", Code("department", "request", "--name", "Marketing Department", "--key-file") == 0);
    var csrPath = Path.Combine(cliHome, "departments", "marketing-department", "request.csr.pem");
    var cliKey = Department.RequestKeyFingerprint(new Home(cliHome), "Marketing Department");
    Expect("46ca authority sign without the key the department gave is refused", Code("authority", "sign", "--request", csrPath, "--name", "Marketing Department") == 2);
    Expect("46cb ...and with another key it is refused too", Code("authority", "sign", "--request", csrPath, "--name", "Marketing Department", "--key", "0000 0000 0000 0000") == 2);
    Expect("46c authority sign", Code("authority", "sign", "--request", csrPath, "--name", "Marketing Department", "--key", cliKey) == 0);
    var certPath = Directory.GetFiles(Path.Combine(cliHome, "authority", "issued"))[0];
    Expect("46d department install", Code("department", "install", "--cert", certPath) == 0);
    var src = Path.Combine(files, "cli.txt"); File.WriteAllText(src, "cli test");
    Expect("46e seal with the fields as options", Code("seal", src, "--made-by", "J. Smith", "--made-for", "Leasing team", "--what", "Test file") == 0);
    var res = Cli("check", Path.Combine(files, "cli.sealed.txt"), "--home", cliHome);
    Expect("46f check says VERIFIED, exit 0, and names the issuing department", res.Code == 0 && res.Out.Contains("VERIFIED") && res.Out.Contains("Issued by     IT Department, Example Property Group"), res.Out + res.Err);
    var folderRes = Cli("check", files, "--trust", Path.Combine(cliHome, "trust"));
    Expect("46g checking a folder returns failure when any file fails and counts them", folderRes.Code == 1 && folderRes.Out.Contains("files passed"));
    var json = Cli("check", Path.Combine(files, "cli.sealed.txt"), "--home", cliHome, "--json");
    Expect("46h --json gives a machine readable answer", JsonNode.Parse(json.Out)![0]!["status"]!.ToString() == "VERIFIED" && JsonNode.Parse(json.Out)![0]!["details"]!["issued_by"]!.ToString() == "IT Department");
    Expect("46i a check with no trust folder fails closed (exit 2)", Cli("check", src, "--trust", Path.Combine(tempRoot, "nowhere")).Code == 2);
    Expect("46j seal with a missing required field exits 2 and says which", Cli("seal", src, "--made-by", "x", "--made-for", "y", "--home", cliHome, "--force").Err.Contains("What it is"));
    Expect("46k department list shows READY", Cli("department", "list", "--home", cliHome).Out.Contains("READY"));
}

// trusting the computer's own roots, pinned
Expect("47 the computer's own roots need a pinned company root", Throws<SealException>(() => TrustPolicy.FromSystem([]), "pin-root"));
Expect("47b a pin that is not a SHA 256 fingerprint is refused", Throws<SealException>(() => TrustPolicy.FromSystem(["ABCD"]), "64"));
{
    var systemTrust = TrustPolicy.FromSystem([Crypto.Sha256Hex(caCert)]);
    var rSystem = Checker.Check(good, systemTrust, now);
    Expect("47c our test authority is not in this computer's roots, so system mode refuses it", rSystem.Status == "NOT_TRUSTED", $"{rSystem.Status}: {rSystem.Reason}");
}

// the real keys in the computer's own store
if (skipStore) Console.WriteLine("(skipped the computer's own store tests: add --with-store to run them)");
else
{
    var storeHome = NewCompany("store-company");
    var storeName = "Sonset Store Test " + Guid.NewGuid().ToString("N")[..6];
    var request = Department.Request(storeHome, storeName, false, now);
    var deptDir = Directory.GetDirectories(storeHome.Departments)[0];
    var identityJson = (JsonObject)JsonNode.Parse(File.ReadAllText(Path.Combine(deptDir, "identity.json")))!;
    var thumb = (string)identityJson["key_thumbprint"]!;
    try
    {
        Expect("48 the department's key is in the computer's own store", OsKeyStore.Find(thumb) != null);
        var certFile = Authority.SignRequest(storeHome, File.ReadAllBytes(Path.Combine(deptDir, "request.csr.pem")), storeName, 100, now);
        Department.Install(storeHome, null, File.ReadAllBytes(certFile));
        var storeIdentity = Department.Load(storeHome, null);
        var sealedFile = Seal(doc, storeIdentity);
        Verdicts("48b sealed with the stored key, no password, no prompt, and it checks", sealedFile, storeHome.Trust, "VERIFIED");
        using var vessel = OsKeyStore.Find(thumb)!;
        using var key = vessel.GetECDsaPrivateKey()!;
        var blocked = false;
        try { key.ExportParameters(true); } catch (CryptographicException) { blocked = true; }
        Expect("48c the stored key cannot be exported, so it cannot be copied off the computer", blocked);
    }
    finally
    {
        Department.Remove(storeHome, Path.GetFileName(deptDir));
    }
    Expect("48d removing the department takes its key out of the store", OsKeyStore.Find(thumb) == null);
}

// our seals checked by openssl, a second, independent implementation
if (File.Exists("/usr/bin/openssl"))
{
    var env2 = ReadEnvelope(Seal(doc, leasing), out _);
    var work = Path.Combine(tempRoot, "ossl"); Directory.CreateDirectory(work);
    File.WriteAllText(Path.Combine(work, "cert.pem"), (string)env2["cert"]!);
    File.WriteAllBytes(Path.Combine(work, "sig.bin"), Convert.FromBase64String((string)env2["signature"]!));
    File.WriteAllBytes(Path.Combine(work, "data.bin"), Canonical.Bytes((JsonObject)env2["signed"]!.DeepClone()));
    string Ossl(params string[] a)
    {
        var p = Process.Start(new ProcessStartInfo("/usr/bin/openssl", a) { RedirectStandardOutput = true, RedirectStandardError = true, WorkingDirectory = work })!;
        var text = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd(); p.WaitForExit(); return text;
    }
    File.WriteAllText(Path.Combine(work, "pub.pem"), Ossl("x509", "-in", "cert.pem", "-noout", "-pubkey"));
    Expect("50 openssl verifies the signature on a seal this tool made", Ossl("dgst", "-sha256", "-verify", "pub.pem", "-signature", "sig.bin", "data.bin").Contains("Verified OK"));
}

// ===================================================================================================
// Holes found in review: each repro became a test.
// ===================================================================================================
void Sh(string command)
{
    using var p = Process.Start(new ProcessStartInfo("/bin/sh", ["-c", command]) { RedirectStandardError = true, RedirectStandardOutput = true })!;
    p.WaitForExit();
}

var signerUse = new Action<CertificateRequest>(r =>
{
    r.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
    r.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
    r.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.4") }, true));
});
byte[] Csr(string cn, ECDsa key) => new CertificateRequest(Names.Build(cn, null), key, HashAlgorithmName.SHA256).CreateSigningRequest();

var v2 = ReadEnvelope(beforeLeasing, out _);
Expect("1e new seals are version 2 and the signature covers the signing certificate",
    (int)v2["signed"]!["v"]! == 2 && (string)v2["signed"]!["signer_sha256"]! == Crypto.Sha256Hex(leasing.Certificate).ToLowerInvariant());

// finding 3: a key certified twice, and a certificate swapped for another one on the same key
{
    var shortDesk = MakeDepartment(home, "Short Desk");
    var csrBytes = File.ReadAllBytes(Path.Combine(home.Departments, "short-desk", "request.csr.pem"));
    Cli("authority", "revoke", "--home", home.Root, "--name", "Short Desk", "--reason", "key stolen");
    Expect("51 the authority will not certify a key it certified before, even after withdrawing it",
        Throws<SealException>(() => Authority.SignRequest(home, csrBytes, "Short Desk", 100, now), "certified before"));
    using var sameKey = ECDsa.Create();
    sameKey.ImportFromPem(File.ReadAllText(Path.Combine(home.Departments, "short-desk", "key.pem")));
    Expect("51b one key cannot be certified under a second name",
        Throws<SealException>(() => Authority.SignRequest(home, Csr("Alias Desk", sameKey), "Alias Desk", 100, now), "certified before"));
    var sd = Seal(doc, shortDesk);
    var sdEnv = ReadEnvelope(sd, out var sdBody);
    using var twin = IssueRaw(signerUse, sameKey, "Twin Desk");
    var swappedEnv = Clone(sdEnv); swappedEnv["cert"] = twin.ExportCertificatePem();
    var swapPath = Path.Combine(files, "swap.pdf"); WriteWith(swapPath, sdBody, swappedEnv);
    var rSwap = Full(swapPath, trust);
    Expect("52 a new certificate for the same key swapped into an old seal is caught", rSwap.Status == "SEAL_BROKEN" && rSwap.Reason.Contains("swapped"), $"{rSwap.Status}: {rSwap.Reason}");
}

// finding 2: the file changes while it is being checked
if (!OperatingSystem.IsWindows())
{
    var raced = Path.Combine(files, "raced.bin"); File.Copy(beforeLeasing, raced, true);
    Checker.AfterHashHook = p =>
    {
        var cut = SealFormat.ReadTrailer(p)!.BodyLength;
        Sh($"dd if=/dev/null of='{p}' bs=1 seek={cut} 2>/dev/null; printf 'plain text now' >> '{p}'");
    };
    string racedVerdict;
    try { racedVerdict = Verdict(raced, trust); } finally { Checker.AfterHashHook = null; }
    Expect("53 a seal cut off while the check is running means the file is not verified", racedVerdict == "CHANGED", racedVerdict);
    Verdicts("53b ...and the next check agrees there is no seal", raced, trust, "NO_SEAL");
}

// finding 4 and 5: nothing from a file name or a seal can fake the screen
{
    var evilDir = Path.Combine(files, "evil"); Directory.CreateDirectory(evilDir);
    var evilPath = Path.Combine(evilDir, "invoice.pdf\n\u001b[1;32mVERIFIED   invoice.pdf\n             Sealed by     Finance Department");
    // Windows does not allow such a file name, so there the screen text is tried on the same name without a real file.
    CheckResult evilResult;
    if (OperatingSystem.IsWindows()) evilResult = new CheckResult(evilPath, "NO_SEAL", "This file carries no seal.");
    else { File.WriteAllText(evilPath, "x"); evilResult = Checker.Check(evilPath, TrustPolicy.FromFolder(trust, now), now); }
    var shown = Checker.Render(evilResult, false);
    Expect("54 a file name cannot fake lines or colours on the screen", !shown.Contains('\u001b') && shown.Split('\n').Length == 2 && shown.Contains("\\u{1B}"), shown);
    var hostile = new CheckResult("f", "VERIFIED", "ok", new CheckDetails("Bob\u001b[2A", "Org\nFake line", "I‮T", null, "AAAA", now, now.AddDays(1),
        [new("Sealed by", "x\u001b[31m"), new("Weird\nkey", "v")], ""));
    var text = Checker.Render(hostile, false);
    Expect("54b hostile names and fields inside a seal cannot fake lines either", !text.Contains('\u001b') && !text.Contains('‮') && text.Split('\n').Length == 8 && text.Contains("Extra: Sealed by"), text);
    Expect("54c hidden characters become visible escapes and accents stay", Display.Safe("a\u001bb‮c​d Zoë") == "a\\u{1B}b\\u{202E}c\\u{200B}d Zoë");
}
{
    string Forge(string name, Func<JsonObject> claims)
    {
        var data = File.ReadAllBytes(doc);
        var signed = new JsonObject
        {
            ["v"] = 2, ["file_sha256"] = SealFormat.HashPrefix(doc, data.Length), ["file_size"] = (long)data.Length, ["sealed_at"] = Time.Iso(now),
            ["claims"] = claims(), ["signer_sha256"] = Crypto.Sha256Hex(leasing.Certificate).ToLowerInvariant()
        };
        var envelope = new JsonObject
        {
            ["signed"] = signed, ["signature"] = Convert.ToBase64String(leasing.Sign(Canonical.Bytes(signed))), ["cert"] = leasing.Certificate.ExportCertificatePem()
        };
        var path = Path.Combine(files, name); WriteWith(path, data, envelope); return path;
    }
    JsonObject Good() => new() { ["Made by"] = "J. Smith", ["Made for"] = "Leasing team", ["What it is"] = "Listing sheet" };
    Verdicts("55 a forged seal with every field right passes (sanity: the forger really holds a key)", Forge("f0.pdf", Good), trust, "VERIFIED");
    Verdicts("55b a department cannot add a field that fakes a screen line", Forge("f1.pdf", () => { var c = Good(); c["Sealed by"] = "Finance Department, Example Property Group"; return c; }), trust, "NOT_TRUSTED");
    Verdicts("55c a seal with no fields at all is refused", Forge("f2.pdf", () => new JsonObject()), trust, "NOT_TRUSTED");
    Verdicts("55d a seal missing a required field is refused", Forge("f3.pdf", () => { var c = Good(); c.Remove("Made for"); return c; }), trust, "NOT_TRUSTED");
    Verdicts("55e a field with control characters is refused", Forge("f4.pdf", () => { var c = Good(); c["Made by"] = "x\u001b[2A"; return c; }), trust, "NOT_TRUSTED");
    Verdicts("55f a field longer than 300 characters is refused", Forge("f5.pdf", () => { var c = Good(); c["What it is"] = new string('x', 301); return c; }), trust, "NOT_TRUSTED");
}

// finding 6: names the authority signs
{
    using var k = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    Expect("56 a look alike name (a Cyrillic letter) is caught because the person types the name themselves",
        Throws<SealException>(() => Authority.SignRequest(home, Csr("Mаrketing Desk", k), "Marketing Desk", 100, now), "you said"));
    Expect("56b a name with a double space is refused", Throws<SealException>(() => Authority.SignRequest(home, Csr("Marketing  Desk", k), "Marketing  Desk", 100, now), "single spaces"));
    Expect("56c a name with an invisible character is refused", Throws<SealException>(() => Authority.SignRequest(home, Csr("Mark​eting Desk", k), "Mark​eting Desk", 100, now), "invisible"));
    Expect("56d a name with a direction changing character is refused", Throws<SealException>(() => Authority.SignRequest(home, Csr("Desk‮", k), "Desk‮", 100, now), "invisible"));
    Expect("56e a department cannot take the issuing department's own name", Throws<SealException>(() => Authority.SignRequest(home, Csr("IT Department", k), "IT Department", 100, now), "own name"));
    Expect("56f a certificate cannot be asked for longer than three years", Throws<SealException>(() => Authority.SignRequest(home, Csr("Fresh Desk", k), "Fresh Desk", 2000, now), "at most"));
    Expect("56g the department itself cannot ask for such a name either", Throws<SealException>(() => Department.Request(home, "Marketing  Desk", true, now), "single spaces"));
    Expect("56h a name with accents and punctuation is fine", Names.CleanStrict("Département Ventes, Québec", "name") == "Département Ventes, Québec");
}

// finding 7: pin the authority, show its fingerprint, and never go back to an older withdrawn list
{
    var caFp = Crypto.Sha256Hex(caCert);
    Expect("57 the authority in a trust folder must match a pin when one is given", Throws<SealException>(() => TrustPolicy.FromFolder(trust, now, ["AB".PadRight(64, '0')]), "pinned"));
    var pinned = Checker.Check(beforeLeasing, TrustPolicy.FromFolder(trust, now, [caFp]), now);
    Expect("57b with the right pin it passes and shows the authority fingerprint", pinned.Ok && Checker.Render(pinned, false).Contains("fingerprint " + Crypto.ShortFingerprint(caCert)));

    var rollHome = NewCompany("roll");
    var rollRoot = Path.Combine(tempRoot, "roll-old-trust"); Directory.CreateDirectory(rollRoot);
    var rollDept = MakeDepartment(rollHome, "Roll Desk");
    var rollFile = Seal(doc, rollDept);
    var state = Path.Combine(tempRoot, "seen.json");
    Authority.Publish(rollHome, now, 30, null);
    File.Copy(Path.Combine(rollHome.Trust, "ca.pem"), Path.Combine(rollRoot, "ca.pem")); File.Copy(Path.Combine(rollHome.Trust, "revoked.json"), Path.Combine(rollRoot, "revoked.json"));
    Authority.Publish(rollHome, now, 30, null);
    var fresh = Checker.Check(rollFile, TrustPolicy.FromFolder(rollHome.Trust, now, null, state), now);
    var rolledBack = Checker.Check(rollFile, TrustPolicy.FromFolder(rollRoot, now, null, state), now);
    Expect("58 the newest withdrawn list passes", fresh.Ok, fresh.Reason);
    Expect("58b an older list is refused once a newer one has been seen", rolledBack.Status == "CANNOT_CONFIRM" && rolledBack.Reason.Contains("older"), $"{rolledBack.Status}: {rolledBack.Reason}");
    Expect("58c the list number counts up with every publish", (int)((JsonObject)JsonNode.Parse(File.ReadAllText(rollHome.RevokedList))!)["number"]! == 3);
}

// finding 8: the command line does not lie by omission
{
    var cliTrust = Path.Combine(tempRoot, "cli-company", "trust");
    var cliSealed = Path.Combine(files, "cli.sealed.txt");
    var caFp = Crypto.Sha256Hex(caCert);
    Expect("59 an unknown option is refused instead of swallowing the next word", Cli("check", cliSealed, "--trsut", "/bin/ls", "--trust", cliTrust).Code == 2);
    Expect("59b --system together with --trust is refused", Cli("check", cliSealed, "--system", "--trust", cliTrust, "--pin-root", caFp).Code == 2);
    Expect("59c the test only options are refused in real use", Cli("check", cliSealed, "--trust", cliTrust, "--now", "2030-01-01").Code == 2
        && Cli("seal", other, "--made-by", "a", "--made-for", "b", "--what", "c", "--sealed-at", "2020-01-01", "--home", home.Root).Code == 2);
    // An environment variable (the old way to unlock them) must not work: anyone who can set one could backdate a check.
    Environment.SetEnvironmentVariable("SONSETSEAL_TEST", "1");
    var envOnly = Cli("check", cliSealed, "--trust", cliTrust, "--now", "2030-01-01").Code;
    Environment.SetEnvironmentVariable("SONSETSEAL_TEST", null);
    CliApp.AllowTestOptions = true;
    var allowed = Cli("check", cliSealed, "--trust", cliTrust, "--now", "2030-01-01").Code;
    CliApp.AllowTestOptions = false;
    Expect("59d ...and accepted only when the test program turns them on inside the process", allowed == 1);
    Expect("59e ...and an environment variable cannot turn them on", envOnly == 2);
    Expect("59f a value that is another option is refused, not swallowed", Cli("check", cliSealed, "--trust", "--json").Code == 2);
    Expect("59g a single dash word is not quietly taken for a file name", Cli("check", "-x", "--trust", cliTrust).Code == 2);
    Expect("59h after -- a file name may start with a dash", Cli("check", "--trust", cliTrust, "--", "-no-such-file.txt").Out.Contains("-no-such-file.txt"));
    Expect("59i a silly number of days is refused", Cli("authority", "publish", "--list-days", "999999", "--home", home.Root).Code == 2);
    var dots = Path.Combine(files, "dots"); Directory.CreateDirectory(dots); File.WriteAllText(Path.Combine(dots, ".payload.txt"), "unsealed");
    var dotRun = Cli("check", dots, "--trust", cliTrust);
    Expect("60 a hidden file in a folder is checked, not skipped", dotRun.Code == 1 && dotRun.Out.Contains("NO SEAL") && dotRun.Out.Contains(".payload.txt"), dotRun.Out);
    Expect("60b two files with the same name in different folders show their full paths", Cli("check", dots, "--trust", cliTrust).Out.Contains(Path.Combine(files, "dots")));
}

// finding 9: a named pipe in a folder
if (!OperatingSystem.IsWindows())
{
    var pipeDir = Path.Combine(files, "pipes"); Directory.CreateDirectory(pipeDir);
    var pipe = Path.Combine(pipeDir, "stuck.fifo"); Sh($"mkfifo '{pipe}'");
    var waited = Stopwatch.StartNew();
    var rp = Checker.Check(pipe, TrustPolicy.FromFolder(trust, now), now);
    Expect("61 a named pipe cannot hang the check", rp.Status == "UNREADABLE" && waited.Elapsed.TotalSeconds < 20, $"{rp.Status} after {waited.Elapsed.TotalSeconds:F1}s");
}

// rough edges
{
    var lower = Path.Combine(files, "lower.txt"); File.WriteAllText(lower, "original");
    Expect("62 a different spelling of the original's name is refused", Throws<SealException>(() => Sealer.Seal(lower, leasing, Fields3(), Path.Combine(files, "LOWER.TXT"), false, true), "never overwrite") && File.ReadAllText(lower) == "original");
    var link = Path.Combine(files, "link-to-original.txt");
    if (!OperatingSystem.IsWindows()) File.CreateSymbolicLink(link, lower);
    Expect("62b a link to the original is refused as the output", OperatingSystem.IsWindows() || (Throws<SealException>(() => Sealer.Seal(lower, leasing, Fields3(), link, false, true), "never overwrite") && File.ReadAllText(lower) == "original"));
    if (!OperatingSystem.IsWindows())
    {
        var secret = Path.Combine(files, "secret.txt"); File.WriteAllText(secret, "private"); File.SetUnixFileMode(secret, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        var victim = Path.Combine(files, "victim.txt"); File.WriteAllText(victim, "keep me");
        var secretOut = Path.Combine(files, "secret.out.txt");
        File.CreateSymbolicLink(secretOut + ".part", victim);
        Sealer.Seal(secret, leasing, Fields3(), secretOut);
        Expect("63 a link planted at the old temporary name is not followed", File.ReadAllText(victim) == "keep me");
        Expect("63b the sealed copy of a private file stays private", (File.GetUnixFileMode(secretOut) & (UnixFileMode.GroupRead | UnixFileMode.OtherRead)) == 0);
        Expect("63c no temporary file is left behind", Directory.GetFiles(files, "secret.out.txt.*.part").Length == 0);
    }
    Expect("64 a name with several parts in one place does not crash the reader", Names.Parts(new X500DistinguishedName("CN=Bob+OU=Sales, O=Acme")).Organisation == "Acme");
    {
        MakeDepartment(home, "Renewal Desk");
        Cli("authority", "revoke", "--home", home.Root, "--name", "Renewal Desk", "--reason", "first lost");
        Department.Remove(home, "Renewal Desk");
        MakeDepartment(home, "Renewal Desk");
        var res = Cli("authority", "revoke", "--home", home.Root, "--name", "Renewal Desk", "--reason", "lost again");
        Expect("65 withdrawing by name still works when the name has had two certificates", res.Code == 0 && res.Out.Contains("Withdrew 1 certificate"), res.Out + res.Err);
    }
    var dupPayload2 = Encoding.ASCII.GetString(payload).Replace("\"cert\":", "\"cert\":\"x\",\"cert\":");
    var dup2 = Path.Combine(files, "dup2.bin"); WriteRaw(dup2, leasingBody, Encoding.ASCII.GetBytes(dupPayload2));
    Verdicts("66 a repeated field name anywhere in the seal is damaged", dup2, trust, "DAMAGED");
}

// ===================================================================================================
// The automatic folders: nobody types anything per file.
// ===================================================================================================
{
    var bxHome = NewCompany("boxco");
    MakeDepartment(bxHome, "Marketing Department");
    using var bxCa = X509Certificate2.CreateFromPem(File.ReadAllText(bxHome.CaPem));
    var sealBox = Path.Combine(tempRoot, "Seal box");
    Boxes.SetupSealBox(sealBox, new Boxes.SealDefaults("Marketing Department", "Marketing Department", "Leasing team", "Owned by Example Property Group", null, null, null));
    var bxDrop = Path.Combine(sealBox, "Drop here");
    File.WriteAllText(Path.Combine(bxDrop, "Front of 12 Example St.txt"), "photo bytes one");
    Directory.CreateDirectory(Path.Combine(bxDrop, "Finance team"));
    File.WriteAllText(Path.Combine(bxDrop, "Finance team", "Quarter report.txt"), "report bytes");
    File.WriteAllText(Path.Combine(bxDrop, ".DS_Store"), "junk");
    File.WriteAllText(Path.Combine(bxDrop, "half written.part"), "x");
    var bxLater = bxHome.Root;
    var bxStill = Boxes.RunSealBoxOnce(bxHome, sealBox, Time.Now(), TimeSpan.FromSeconds(60));
    Expect("70 files that were only just saved are left alone until they have sat still", bxStill.Handled == 0 && bxStill.Waiting == 2, $"{bxStill}");
    var bxReport = Boxes.RunSealBoxOnce(bxHome, sealBox, Time.Now().AddSeconds(10), TimeSpan.Zero);
    Expect("70b dropping files seals them with no command: two sealed, no problems", bxReport.Handled == 2 && bxReport.Problems == 0, $"{bxReport}");
    var sealedA = Path.Combine(sealBox, "Sealed", "Front of 12 Example St.sealed.txt");
    var sealedB = Path.Combine(sealBox, "Sealed", "Finance team", "Quarter report.sealed.txt");
    var bxA = Full(sealedA, bxHome.Trust);
    var bxB = Full(sealedB, bxHome.Trust);
    Expect("70c the sealed copies check out, with fields taken from the box and the file name",
        bxA.Ok && bxA.Details!.Claims.First(c => c.Key == "What it is").Value == "Front of 12 Example St"
        && bxA.Details.Claims.First(c => c.Key == "Made for").Value == "Leasing team" && bxA.Details.Claims.Any(c => c.Key == "Rights"), bxA.Reason);
    Expect("70d a folder named for a team inside 'Drop here' sets who the file is for", bxB.Ok && bxB.Details!.Claims.First(c => c.Key == "Made for").Value == "Finance team", bxB.Reason);
    Expect("70e originals move to 'Done', 'Drop here' is emptied of real files, junk and half written files are left alone",
        File.Exists(Path.Combine(sealBox, "Done", "Front of 12 Example St.txt")) && !File.Exists(Path.Combine(bxDrop, "Front of 12 Example St.txt"))
        && File.Exists(Path.Combine(bxDrop, ".DS_Store")) && File.Exists(Path.Combine(bxDrop, "half written.part")));
    // problems
    File.Copy(sealedA, Path.Combine(bxDrop, "Already sealed.txt"));
    var bxProblem = Boxes.RunSealBoxOnce(bxHome, sealBox, Time.Now().AddSeconds(10), TimeSpan.Zero);
    var why = Path.Combine(sealBox, "Problems", "Already sealed.txt.why.txt");
    Expect("71 a file that is already sealed goes to 'Problems' with a plain note", bxProblem.Problems == 1 && File.Exists(why) && File.ReadAllText(why).Contains("already carries a seal"));
    var noDefaultBox = Path.Combine(tempRoot, "Seal box two");
    Boxes.SetupSealBox(noDefaultBox, new Boxes.SealDefaults("Marketing Department", "Marketing Department", null, null, null, null, null));
    File.WriteAllText(Path.Combine(noDefaultBox, "Drop here", "No team.txt"), "x");
    var bxNoTeam = Boxes.RunSealBoxOnce(bxHome, noDefaultBox, Time.Now().AddSeconds(10), TimeSpan.Zero);
    Expect("71b a file with nobody to be for goes to 'Problems' and says why", bxNoTeam.Problems == 1 && File.ReadAllText(Path.Combine(noDefaultBox, "Problems", "No team.txt.why.txt")).Contains("who this file is for"));

    // the receiver's box
    var checkBox = Path.Combine(tempRoot, "Check box");
    Boxes.SetupCheckBox(checkBox, bxHome.Trust, [Crypto.Sha256Hex(bxCa)]);
    var incoming = Path.Combine(checkBox, "Incoming");
    File.Copy(sealedA, Path.Combine(incoming, "genuine.txt"));
    var edited = File.ReadAllBytes(sealedA); edited[2] ^= 1; File.WriteAllBytes(Path.Combine(incoming, "edited.txt"), edited);
    File.WriteAllText(Path.Combine(incoming, "never sealed.txt"), "plain");
    File.Copy(fake, Path.Combine(incoming, "impostor.pdf"));
    var bxCheck = Boxes.RunCheckBoxOnce(bxHome, checkBox, Time.Now().AddSeconds(10), TimeSpan.Zero);
    Expect("72 arriving files are checked with no command: one verified, three rejected", bxCheck.Handled == 1 && bxCheck.Problems == 3, $"{bxCheck}");
    Expect("72b the genuine file lands in 'Verified' and nothing else does",
        File.Exists(Path.Combine(checkBox, "Verified", "genuine.txt")) && Directory.GetFiles(Path.Combine(checkBox, "Verified")).Length == 1);
    Expect("72c every rejected file comes with a note saying why", new[] { "edited.txt", "never sealed.txt", "impostor.pdf" }.All(n =>
        File.Exists(Path.Combine(checkBox, "Rejected", n)) && File.ReadAllText(Path.Combine(checkBox, "Rejected", n + ".why.txt")).StartsWith("Do not open this file.")));
    Expect("72d 'Incoming' is left empty and a log is kept", Directory.GetFiles(incoming).Length == 0 && File.ReadAllText(Path.Combine(checkBox, "log.txt")).Contains("REJECTED"));

    // when the check cannot run, nothing moves
    var brokenBox = Path.Combine(tempRoot, "Check box broken");
    Boxes.SetupCheckBox(brokenBox, Path.Combine(tempRoot, "no-such-trust-folder"), []);
    File.WriteAllText(Path.Combine(brokenBox, "Incoming", "waiting.txt"), "x");
    var bxBroken = Boxes.RunCheckBoxOnce(bxHome, brokenBox, Time.Now().AddSeconds(10), TimeSpan.Zero);
    Expect("73 without a trust folder nothing is moved and the reason is logged", bxBroken.Handled + bxBroken.Problems == 0 && File.Exists(Path.Combine(brokenBox, "Incoming", "waiting.txt"))
        && File.ReadAllText(Path.Combine(brokenBox, "log.txt")).Contains("CANNOT CHECK"));
    var wrongPinBox = Path.Combine(tempRoot, "Check box wrong pin");
    Boxes.SetupCheckBox(wrongPinBox, bxHome.Trust, ["AB".PadRight(64, '0')]);
    File.Copy(sealedA, Path.Combine(wrongPinBox, "Incoming", "genuine.txt"));
    Boxes.RunCheckBoxOnce(bxHome, wrongPinBox, Time.Now().AddSeconds(10), TimeSpan.Zero);
    Expect("73b a trust folder that fails its pin moves nothing either", File.Exists(Path.Combine(wrongPinBox, "Incoming", "genuine.txt")) && !File.Exists(Path.Combine(wrongPinBox, "Verified", "genuine.txt")));

    // through the command line
    var cliBox = Path.Combine(tempRoot, "cli seal box");
    var setup = Cli("seal-box", "setup", "--folder", cliBox, "--department", "Marketing Department", "--made-for", "Leasing team", "--home", bxHome.Root);
    File.WriteAllText(Path.Combine(cliBox, "Drop here", "Via the command line.txt"), "cli bytes");
    var runOnce = Cli("seal-box", "run", "--folder", cliBox, "--once", "--settle", "0", "--home", bxHome.Root);
    Expect("74 the command line sets up and runs a seal box once", setup.Code == 0 && runOnce.Code == 0 && runOnce.Out.Contains("Handled 1")
        && File.Exists(Path.Combine(cliBox, "Sealed", "Via the command line.sealed.txt")), setup.Err + runOnce.Out + runOnce.Err);
    var cliCheckBox = Path.Combine(tempRoot, "cli check box");
    Cli("check-box", "setup", "--folder", cliCheckBox, "--trust", bxHome.Trust, "--home", bxHome.Root);
    File.Copy(Path.Combine(cliBox, "Sealed", "Via the command line.sealed.txt"), Path.Combine(cliCheckBox, "Incoming", "arrived.txt"));
    var checkOnce = Cli("check-box", "run", "--folder", cliCheckBox, "--once", "--settle", "0", "--home", bxHome.Root);
    Expect("74b the command line runs a check box once", checkOnce.Code == 0 && File.Exists(Path.Combine(cliCheckBox, "Verified", "arrived.txt")), checkOnce.Out + checkOnce.Err);
    Expect("74c an unknown option on a box command is refused", Cli("seal-box", "run", "--folder", cliBox, "--onse", "--home", bxHome.Root).Code == 2);

    // starting at login
    var plist = Boxes.MacLaunchAgent("ca.sonset.test", "/Applications/Sonset/sonsetseal", ["seal-box", "run", "--folder", "/a & b/<x>"]);
    Expect("75 the Mac start at login file is well formed and keeps odd characters safe", plist.Contains("<key>RunAtLoad</key><true/>") && plist.Contains("<string>/a &amp; b/&lt;x&gt;</string>"));
    Expect("75b the Windows start at login file runs hidden", Boxes.WindowsStartupScript("C:\\Tools\\sonsetseal.exe", ["seal-box", "run"]).Contains("Wscript.Shell") && Boxes.WindowsStartupScript("C:\\Tools\\sonsetseal.exe", ["seal-box", "run"]).Contains(", 0, False"));
    var auto = Cli("seal-box", "autostart", "--folder", cliBox, "--home", bxHome.Root);
    Expect("75c autostart only shows what it would write unless asked to install", auto.Code == 0 && auto.Out.Contains("Add --install") && !auto.Out.Contains("Wrote"));
}

// ===================================================================================================
// Seamless setup: a company share, one command per department, one command to approve, trust that updates itself.
// ===================================================================================================
{
    var stItHome = Path.Combine(tempRoot, "st-it-home");
    var stDeptHome = Path.Combine(tempRoot, "st-dept-home");
    var stShare = Path.Combine(tempRoot, "Company share");
    var stBoxes = Path.Combine(tempRoot, "st-dept-boxes");
    var stIt = new Home(stItHome);
    var stDept = new Home(stDeptHome);
    Authority.Init(stIt, "Example Property Group", "IT Department", 10, 30, now);
    var shareRun = Cli("authority", "share-setup", "--share", stShare, "--home", stItHome);
    Expect("80 IT sets up the company share once", shareRun.Code == 0 && File.Exists(Path.Combine(stShare, "Trust", "ca.pem")) && File.Exists(Path.Combine(stShare, "Trust", "revoked.json")), shareRun.Out + shareRun.Err);

    var stPin = Crypto.Sha256Hex(X509Certificate2.CreateFromPem(File.ReadAllText(stIt.CaPem)));
    Expect("80b setup without reaching the share fails plainly", Cli("setup", "--share", Path.Combine(tempRoot, "no-share"), "--department", "Marketing Department", "--pin-root", stPin, "--home", stDeptHome).Code == 2);
    var noPin = Cli("setup", "--share", stShare, "--department", "Marketing Department", "--box-folder", stBoxes, "--key-file", "--no-autostart", "--home", stDeptHome);
    Expect("80c setup without a pin is refused, and makes nothing", noPin.Code == 2 && noPin.Err.Contains("--pin-root") && noPin.Err.Contains("--trust-on-first-use") && !Directory.Exists(Path.Combine(stDeptHome, "departments")) && !Directory.Exists(stBoxes), noPin.Out + noPin.Err);
    Expect("80d a pin that is not a fingerprint is refused, not ignored", Cli("setup", "--share", stShare, "--department", "Marketing Department", "--pin-root", "not a fingerprint", "--box-folder", stBoxes, "--key-file", "--no-autostart", "--home", stDeptHome).Code == 2 && !Directory.Exists(stBoxes));
    var shareText = shareRun.Out;
    Expect("80e share setup shows the pin and the command to give departments", shareText.Contains(stPin) && shareText.Contains("--pin-root " + stPin) && shareText.Contains("authority approve"), shareText);
    var setupRun = Cli("setup", "--share", stShare, "--department", "Marketing Department", "--made-for", "Leasing team", "--rights", "Owned by Example Property Group",
        "--box-folder", stBoxes, "--key-file", "--no-autostart", "--pin-root", stPin, "--home", stDeptHome);
    var stSealBox = Path.Combine(stBoxes, "Seal box");
    var stCheckBox = Path.Combine(stBoxes, "Check box");
    Expect("81 one command sets up a department: key, request in the share, both boxes", setupRun.Code == 0
        && File.Exists(Path.Combine(stShare, "Requests", "marketing-department.csr.pem")) && Directory.Exists(Path.Combine(stSealBox, "Drop here")) && Directory.Exists(Path.Combine(stCheckBox, "Incoming")), setupRun.Out + setupRun.Err);
    var stSettings = (JsonObject)JsonNode.Parse(File.ReadAllText(Path.Combine(stCheckBox, "settings.json")))!;
    Expect("81b the company's trust folder arrived by itself and only the pinned authority is trusted", File.Exists(Path.Combine(stCheckBox, "trust", "ca.pem"))
        && stSettings["pin_roots"]!.AsArray().Count == 1 && stSettings["pin_roots"]![0]!.GetValue<string>() == stPin);
    var stKey = Department.RequestKeyFingerprint(stDept, "Marketing Department");
    Expect("81d setup tells the department which key fingerprint to give the issuing department", setupRun.Out.Contains(stKey) && Regex.IsMatch(stKey, "^[0-9A-F]{4}( [0-9A-F]{4}){3}$"), setupRun.Out);
    Expect("81e the seal box remembers the pin too", ((JsonObject)JsonNode.Parse(File.ReadAllText(Path.Combine(stSealBox, "settings.json")))!)["pin_roots"]![0]!.GetValue<string>() == stPin);
    Expect("81c running setup again is harmless", Cli("setup", "--share", stShare, "--department", "Marketing Department", "--made-for", "Leasing team", "--box-folder", stBoxes, "--key-file", "--no-autostart", "--pin-root", stPin, "--home", stDeptHome).Code == 0);

    File.WriteAllText(Path.Combine(stSealBox, "Drop here", "Saved before approval.txt"), "bytes");
    var stWait = Boxes.RunSealBoxOnce(stDept, stSealBox, Time.Now().AddSeconds(10), TimeSpan.Zero);
    Expect("82 before IT approves, files wait in 'Drop here' and the box says why", stWait.Handled == 0 && stWait.Waiting == 1 && File.Exists(Path.Combine(stSealBox, "Drop here", "Saved before approval.txt"))
        && File.ReadAllText(Path.Combine(stSealBox, "status.txt")).Contains("Waiting for the issuing department"));
    var inboxRun = Cli("authority", "inbox", "--home", stItHome);
    Expect("82b IT sees who is waiting", inboxRun.Out.Contains("Marketing Department") && inboxRun.Out.Contains("WAITING"), inboxRun.Out);
    Expect("82c approving a name nobody asked for is refused", Cli("authority", "approve", "--name", "Finance Department", "--key", stKey, "--home", stItHome).Code == 2);
    Expect("82d approving without the key the department gave is refused", Cli("authority", "approve", "--name", "Marketing Department", "--home", stItHome).Code == 2
        && !File.Exists(Path.Combine(stShare, "Certificates", "marketing-department.pem")));
    // someone who can write to the share swaps the waiting request for one holding their own key
    var realRequest = File.ReadAllBytes(Path.Combine(stShare, "Requests", "marketing-department.csr.pem"));
    using (var evilKey = ECDsa.Create(ECCurve.NamedCurves.nistP256))
        File.WriteAllText(Path.Combine(stShare, "Requests", "marketing-department.csr.pem"), PemEncoding.WriteString("CERTIFICATE REQUEST",
            new CertificateRequest(Names.Build("Marketing Department", null), evilKey, HashAlgorithmName.SHA256).CreateSigningRequest()) + "\n");
    var swapped = Cli("authority", "approve", "--name", "Marketing Department", "--key", stKey, "--home", stItHome);
    Expect("82e a request swapped in the share is not approved: the key is not the one the department gave", swapped.Code == 2 && swapped.Err.Contains("do not approve") && !File.Exists(Path.Combine(stShare, "Certificates", "marketing-department.pem")), swapped.Out + swapped.Err);
    File.WriteAllBytes(Path.Combine(stShare, "Requests", "marketing-department.csr.pem"), realRequest);
    Expect("82f a key that is too short to mean anything is refused", Cli("authority", "approve", "--name", "Marketing Department", "--key", "AB", "--home", stItHome).Code == 2);
    var approveRun = Cli("authority", "approve", "--name", "Marketing Department", "--key", stKey, "--home", stItHome);
    Expect("83 IT approves with one command", approveRun.Code == 0 && File.Exists(Path.Combine(stShare, "Certificates", "marketing-department.pem")), approveRun.Out + approveRun.Err);
    Expect("83b approving the same request twice is refused (it has been handled)", Cli("authority", "approve", "--name", "Marketing Department", "--key", stKey, "--home", stItHome).Code == 2);

    var stSealed = Boxes.RunSealBoxOnce(stDept, stSealBox, Time.Now().AddSeconds(10), TimeSpan.Zero);
    Expect("84 the department's box installs the certificate by itself and seals what was waiting", stSealed.Handled == 1 && Department.HasCertificate(stDept, "Marketing Department")
        && File.ReadAllText(Path.Combine(stSealBox, "log.txt")).Contains("CERTIFICATE INSTALLED"), $"{stSealed}");
    var stSealedFile = Path.Combine(stSealBox, "Sealed", "Saved before approval.sealed.txt");
    Expect("84b the sealed copy checks out against the company's own trust folder", Full(stSealedFile, Path.Combine(stCheckBox, "trust")).Ok);

    // someone swaps the authority on the share for their own
    var impostorTrust = impostor.Trust;
    File.Copy(Path.Combine(impostorTrust, "ca.pem"), Path.Combine(stShare, "Trust", "ca.pem"), true);
    File.Copy(Path.Combine(impostorTrust, "revoked.json"), Path.Combine(stShare, "Trust", "revoked.json"), true);
    File.Copy(stSealedFile, Path.Combine(stCheckBox, "Incoming", "genuine one.txt"), true);
    var stSwapped = Boxes.RunCheckBoxOnce(stDept, stCheckBox, Time.Now().AddSeconds(10), TimeSpan.Zero);
    Expect("85 a swapped authority on the share is not accepted: the pinned one stays, the genuine file still passes",
        stSwapped.Handled == 1 && File.Exists(Path.Combine(stCheckBox, "Verified", "genuine one.txt")) && File.ReadAllText(Path.Combine(stCheckBox, "log.txt")).Contains("TRUST NOT UPDATED"));
    Authority.Publish(stIt, now, 30, null); // IT publishes again: the share is right again

    // IT withdraws the department; nobody copies anything by hand
    var stRevoke = Cli("authority", "revoke", "--name", "Marketing Department", "--reason", "laptop lost", "--home", stItHome);
    Expect("86 withdrawing a department puts the new list in the share on its own", stRevoke.Code == 0 && File.ReadAllText(Path.Combine(stShare, "Trust", "revoked.json")).Contains("laptop lost")
        &&((JsonObject)JsonNode.Parse(File.ReadAllText(Path.Combine(stShare, "Trust", "revoked.json")))!)["revoked"]!.AsArray().Count == 1);
    File.Copy(stSealedFile, Path.Combine(stCheckBox, "Incoming", "after withdrawal.txt"), true);
    var stAfter = Boxes.RunCheckBoxOnce(stDept, stCheckBox, Time.Now().AddSeconds(10), TimeSpan.Zero);
    var stWhy = File.ReadAllText(Path.Combine(stCheckBox, "Rejected", "after withdrawal.txt.why.txt"));
    Expect("86b the check box refuses that department's files from then on, without anyone touching it", stAfter.Problems == 1 && stWhy.Contains("withdrawn") && stWhy.Contains("laptop lost"), stWhy);
}

// ===================================================================================================
// On screen messages: one short message per batch, with a setting for each box.
// ===================================================================================================
{
    var nSent = new List<(string Title, string Message)>();
    Func<string, string, string> nCatch = (t, m) => { nSent.Add((t, m)); return ""; };
    var nFive = new List<Boxes.BoxNote>
    {
        new("Sealed a.txt", false), new("Sealed b.txt", false), new("Could not seal c.txt. It is already sealed.", true),
        new("Sealed d.txt", false), new("Do not open e.txt. The file was changed after it was sealed.", true)
    };
    var nRep5 = new Boxes.BoxReport(3, 2, 0, nFive);
    var nAll = Boxes.Announce(nRep5, "all", nCatch);
    Expect("90 one batch gives one message: what needs a look first, then a count of the rest",
        nAll == "" && nSent.Count == 1 && nSent[0].Title == "Sonset seal: look at this"
        && nSent[0].Message == "Could not seal c.txt. It is already sealed. Do not open e.txt. The file was changed after it was sealed. And 3 more.", nSent.Count > 0 ? nSent[0].Message : "nothing sent");

    nSent.Clear();
    Boxes.Announce(nRep5, "problems", nCatch);
    Expect("90b the 'problems' setting names only what needs a look", nSent.Count == 1 && !nSent[0].Message.Contains("Sealed") && nSent[0].Message.Contains("e.txt") && !nSent[0].Message.Contains("And "), nSent.Count > 0 ? nSent[0].Message : "nothing sent");

    nSent.Clear();
    var nQuiet = new Boxes.BoxReport(2, 0, 0, [new("Sealed a.txt", false), new("Sealed b.txt", false)]);
    var nQuietResult = Boxes.Announce(nQuiet, "problems", nCatch);
    Expect("90c a quiet batch sends nothing in 'problems' mode", nQuietResult == null && nSent.Count == 0);
    Expect("90d 'off' sends nothing, even for a problem", Boxes.Announce(nRep5, "off", nCatch) == null && nSent.Count == 0);
    Expect("90e a batch with nothing to say sends nothing", Boxes.Announce(new Boxes.BoxReport(0, 0, 2), "all", nCatch) == null && nSent.Count == 0);
    Boxes.Announce(nQuiet, "all", nCatch);
    Expect("90f a calm batch has the plain title", nSent.Count == 1 && nSent[0].Title == "Sonset seal" && nSent[0].Message == "Sealed a.txt. Sealed b.txt.", nSent.Count > 0 ? nSent[0].Message : "");
    Expect("90g a message that could not be shown gives the reason back", Boxes.Announce(nQuiet, "all", (_, _) => "the Mac did not answer in time") == "the Mac did not answer in time");

    // the loop: one message per batch that had something to say, none for quiet passes, and it keeps going after a file trouble
    nSent.Clear();
    using (var nStop = new CancellationTokenSource())
    {
        var nPasses = 0;
        var nLoopOut = new StringWriter();
        Boxes.RunLoop(() =>
        {
            nPasses++;
            if (nPasses == 4) nStop.Cancel();
            if (nPasses == 1) throw new IOException("a file was busy");
            return nPasses switch { 2 => nRep5, 3 => new Boxes.BoxReport(0, 0, 0), _ => new Boxes.BoxReport(1, 0, 0, [new("Sealed z.txt", false)]) };
        }, nLoopOut, nStop.Token, () => "all", nCatch, TimeSpan.FromMilliseconds(5));
        Expect("91 the loop sends one message for each batch with something to say and keeps going after a busy file", nPasses == 4 && nSent.Count == 2 && nLoopOut.ToString().Contains("could not be reached"), $"{nPasses} passes, {nSent.Count} messages");
    }
    nSent.Clear();
    using (var nStop2 = new CancellationTokenSource())
    {
        var nPasses2 = 0;
        Boxes.RunLoop(() => { if (++nPasses2 == 3) nStop2.Cancel(); return nQuiet; }, new StringWriter(), nStop2.Token, () => nPasses2 == 1 ? "all" : "off", nCatch, TimeSpan.FromMilliseconds(5));
        Expect("91b the box's setting is read on every pass, so a change takes effect without a restart", nSent.Count == 1, $"{nSent.Count} messages");
    }

    // a real seal box pass gives the lines for one message
    var nHome = NewCompany("notify-co");
    MakeDepartment(nHome, "Marketing Department");
    var nBox = Path.Combine(tempRoot, "notify seal box");
    Boxes.SetupSealBox(nBox, new Boxes.SealDefaults("Marketing Department", "Marketing Department", "Leasing team", null, null, null, null));
    foreach (var n in new[] { "a", "b", "c" }) File.WriteAllText(Path.Combine(nBox, "Drop here", n + ".txt"), "bytes " + n);
    var nSealReport = Boxes.RunSealBoxOnce(nHome, nBox, Time.Now().AddSeconds(10), TimeSpan.Zero);
    nSent.Clear();
    Boxes.Announce(nSealReport, Boxes.NotifyMode(nBox), nCatch);
    Expect("91c three files sealed in one pass give one message that names the first two", nSealReport.Handled == 3 && nSent.Count == 1 && nSent[0].Message == "Sealed a.txt. Sealed b.txt. And 1 more.", nSent.Count > 0 ? nSent[0].Message : "");
    File.WriteAllText(Path.Combine(nBox, "Drop here", "plain.txt"), "x");
    File.Copy(Path.Combine(nBox, "Sealed", "a.sealed.txt"), Path.Combine(nBox, "Drop here", "twice.txt"));
    var nSealReport2 = Boxes.RunSealBoxOnce(nHome, nBox, Time.Now().AddSeconds(10), TimeSpan.Zero);
    Expect("91d a file that cannot be sealed makes an alert that says why", nSealReport2.Problems == 1 && nSealReport2.Notes!.Any(n => n.Alert && n.Text.Contains("twice.txt") && n.Text.Contains("already carries a seal")), string.Join(" | ", nSealReport2.Notes!.Select(n => n.Text)));

    // settings: saved with the box, kept when setup is run again, refused when nonsense
    var nBox2 = Path.Combine(tempRoot, "notify seal box two");
    var nS1 = Cli("seal-box", "setup", "--folder", nBox2, "--department", "Marketing Department", "--notify", "problems", "--home", nHome.Root);
    Expect("92 the message setting is saved with the box", nS1.Code == 0 && Boxes.NotifyMode(nBox2) == "problems", nS1.Err);
    Cli("seal-box", "setup", "--folder", nBox2, "--department", "Marketing Department", "--home", nHome.Root);
    Expect("92b running setup again without the option keeps the setting", Boxes.NotifyMode(nBox2) == "problems");
    var nBad = Cli("seal-box", "setup", "--folder", nBox2, "--department", "Marketing Department", "--notify", "loud", "--home", nHome.Root);
    Expect("92c a setting that is not all, problems or off is refused", nBad.Code == 2 && nBad.Err.Contains("all, problems or off") && Boxes.NotifyMode(nBox2) == "problems");
    var nCheckBox = Path.Combine(tempRoot, "notify check box");
    Cli("check-box", "setup", "--folder", nCheckBox, "--trust", nHome.Trust, "--notify", "off", "--home", nHome.Root);
    Expect("92d the check box has its own setting", Boxes.NotifyMode(nCheckBox) == "off" && Boxes.NotifyMode(nBox) == "all");
    Expect("92e a missing or broken settings file means 'all'", Boxes.NotifyMode(Path.Combine(tempRoot, "no such box")) == "all");
    File.WriteAllText(Path.Combine(nCheckBox, "settings.json"), "{ not json");
    Expect("92f ...and so does one that cannot be read", Boxes.NotifyMode(nCheckBox) == "all");

    // the real send path: cleaned text, the test command, and no message from a single run
    var nSink = new List<(string, string)>();
    Notify.Sink = (t, m) => nSink.Add((t, m));
    try
    {
        Notify.Send("title", "a\u001b[31mb‮c\nd");
        Expect("93 text from a file name is cleaned before it reaches the screen", nSink.Count == 1 && !nSink[0].Item2.Contains('\u001b') && !nSink[0].Item2.Contains('‮') && !nSink[0].Item2.Contains('\n') && nSink[0].Item2.Contains("\\u{1B}"), nSink.Count > 0 ? nSink[0].Item2 : "");
        nSink.Clear();
        var nTest = Cli("notify-test");
        Expect("93b notify-test sends one test message and says so", nTest.Code == 0 && nSink.Count == 1 && nTest.Out.Contains("Sent a test message") && nSink[0].Item2.Contains("test message"), nTest.Out + nTest.Err);
        nSink.Clear();
        File.WriteAllText(Path.Combine(nBox, "Drop here", "one run.txt"), "x");
        var nOnce = Cli("seal-box", "run", "--folder", nBox, "--once", "--settle", "0", "--home", nHome.Root);
        Expect("93c a single run shows its answer in the terminal and puts nothing on the screen", nOnce.Code == 0 && nOnce.Out.Contains("Handled 1") && nOnce.Out.Contains("Sealed one run.txt") && nSink.Count == 0, nOnce.Out);
        using var nStop3 = new CancellationTokenSource();
        var nPasses3 = 0;
        Boxes.RunLoop(() => { if (++nPasses3 == 1) nStop3.Cancel(); return nQuiet; }, new StringWriter(), nStop3.Token, null, null, TimeSpan.FromMilliseconds(5));
        Expect("93d the loop sends through the real send path by default", nSink.Count == 1 && nSink[0].Item1 == "Sonset seal", $"{nSink.Count}");
    }
    finally { Notify.Sink = null; }
    var nOff = Cli("notify-test");
    Expect("93e with messages switched off notify-test says so and nothing is shown", nOff.Code == 1 && nOff.Out.Contains("switched off"), nOff.Out);
    Expect("93f the same words go in the help", Cli().Out.Contains("notify-test") && Cli().Out.Contains("--notify") && Cli().Out.Contains("uninstall"));
}

// ===================================================================================================
// The check box also watches Downloads and other folders: only files that carry a seal are judged.
// ===================================================================================================
{
    var iHome = NewCompany("inspect-co");
    var iDept = MakeDepartment(iHome, "Marketing Department");
    var iWatch = Path.Combine(tempRoot, "watched downloads");
    Directory.CreateDirectory(iWatch);
    var iBox = Path.Combine(tempRoot, "inspect check box");
    Boxes.SetupCheckBox(iBox, iHome.Trust, [], null, [iWatch], "all");
    byte[] Plain(string text) => Encoding.UTF8.GetBytes(text);
    string Tampered(string path) { var b = File.ReadAllBytes(path); b[5] ^= 1; File.WriteAllBytes(path, b); return path; }
    string SealedAt(string where) { Directory.CreateDirectory(Path.GetDirectoryName(where)!); return Seal(doc, iDept, where); }

    var iGenuine = SealedAt(Path.Combine(iWatch, "Listing photo.pdf"));
    Tampered(SealedAt(Path.Combine(iWatch, "Edited after sealing.pdf")));
    Tampered(SealedAt(Path.Combine(iWatch, "sub", "deeper", "Edited too.pdf")));
    Tampered(SealedAt(Path.Combine(iWatch, "a", "Same name.pdf")));
    Tampered(SealedAt(Path.Combine(iWatch, "b", "Same name.pdf")));
    var iPlain = Path.Combine(iWatch, "notes.txt");
    File.WriteAllBytes(iPlain, Plain("just my own notes"));
    var iPlainBefore = File.GetLastWriteTimeUtc(iPlain);
    var iPartial = Tampered(SealedAt(Path.Combine(iWatch, "still arriving.crdownload")));
    var iHidden = Tampered(SealedAt(Path.Combine(iWatch, ".hidden.pdf")));
    var iHiddenDir = Tampered(SealedAt(Path.Combine(iWatch, ".cache", "tucked away.pdf")));
    var iLinkTarget = Tampered(SealedAt(Path.Combine(files, "link target.pdf")));
    if (!OperatingSystem.IsWindows()) File.CreateSymbolicLink(Path.Combine(iWatch, "link.pdf"), iLinkTarget);

    var iHashes = 0;
    Checker.AfterHashHook = _ => iHashes++;
    try
    {
        // Carries a seal or not
        Expect("94 a sealed file carries a seal, an ordinary file does not, a missing file cannot be told",
            Checker.CarriesSeal(iGenuine) == true && Checker.CarriesSeal(iPlain) == false && Checker.CarriesSeal(Path.Combine(iWatch, "nothing here.pdf")) == null);
        var iDamaged = Path.Combine(files, "damaged for watch.bin"); WriteRaw(iDamaged, File.ReadAllBytes(doc), "{\"not\":\"a seal\"}"u8.ToArray(), length: 99999);
        Expect("94b a seal marker with a damaged block still counts as a sealed file (it must not be trusted)", Checker.CarriesSeal(iDamaged) == true);

        var iNow = () => Time.Now().AddSeconds(10);
        var p1 = Boxes.RunCheckBoxOnce(iHome, iBox, iNow(), TimeSpan.Zero);
        Expect("95 the first look: one genuine file, five bad ones, ordinary files and downloads still arriving not judged", p1.Handled == 1 && p1.Problems == 5, $"handled {p1.Handled}, problems {p1.Problems}, waiting {p1.Waiting}");
        Expect("95b a genuine sealed file stays exactly where it is, and is logged", File.Exists(iGenuine) && File.ReadAllText(Path.Combine(iBox, "log.txt")).Contains("VERIFIED") && File.ReadAllText(Path.Combine(iBox, "log.txt")).Contains("Listing photo.pdf"));
        var iRej = Path.Combine(iBox, "Rejected");
        Expect("95c bad sealed files move to Rejected with a note that says why and where they were found",
            File.Exists(Path.Combine(iRej, "Edited after sealing.pdf")) && !File.Exists(Path.Combine(iWatch, "Edited after sealing.pdf"))
            && File.ReadAllText(Path.Combine(iRej, "Edited after sealing.pdf.why.txt")).Contains("changed after it was sealed")
            && File.ReadAllText(Path.Combine(iRej, "Edited after sealing.pdf.why.txt")).Contains(iWatch)
            && File.Exists(Path.Combine(iRej, "Edited too.pdf")) && !File.Exists(Path.Combine(iWatch, "sub", "deeper", "Edited too.pdf")));
        Expect("95d two bad files with the same name both arrive in Rejected, neither overwrites the other", File.Exists(Path.Combine(iRej, "Same name.pdf")) && File.Exists(Path.Combine(iRej, "Same name (2).pdf")));
        Expect("95e an ordinary file is never touched, moved or named", File.ReadAllText(iPlain) == "just my own notes" && File.GetLastWriteTimeUtc(iPlain) == iPlainBefore
            && p1.Notes!.All(n => !n.Text.Contains("notes.txt")));
        Expect("95f a download that is still arriving is left for later, but a bad sealed file in a hidden folder is not skipped",
            File.Exists(iPartial) && File.Exists(iHidden) && !File.Exists(iHiddenDir) && File.Exists(Path.Combine(iRej, "tucked away.pdf")));
        if (!OperatingSystem.IsWindows())
            Expect("95g a link is not followed: the file it points at is not touched", File.Exists(iLinkTarget) && File.Exists(Path.Combine(iWatch, "link.pdf")) && p1.Notes!.All(n => !n.Text.Contains("link.pdf")));
        Expect("95h one message covers the batch, with the bad ones first", p1.Notes!.Count == 6 && p1.Notes.Count(n => n.Alert) == 5 && Notify.Summary(p1.Notes).Message.StartsWith("Do not open"), string.Join(" | ", p1.Notes.Select(n => n.Text)));
        var iSeenPath = Path.Combine(iBox, "seen.json");
        var iSeen = (JsonObject)JsonNode.Parse(File.ReadAllText(iSeenPath))!;
        Expect("95i what was seen is remembered on disk", iSeen[iGenuine]?["state"]?.ToString() == "verified" && iSeen[iPlain]?["state"]?.ToString() == "noseal");

        // not looked at again
        var hashesAfterFirst = iHashes;
        var p2 = Boxes.RunCheckBoxOnce(iHome, iBox, iNow(), TimeSpan.Zero);
        Expect("96 a second look finds nothing new and reads nothing again", p2.Handled == 0 && p2.Problems == 0 && (p2.Notes?.Count ?? 0) == 0 && iHashes == hashesAfterFirst, $"{p2}, hashed {iHashes - hashesAfterFirst} more");

        // an ordinary file that becomes a sealed one is judged when it changes
        File.Copy(iGenuine, iPlain, true);
        var p3 = Boxes.RunCheckBoxOnce(iHome, iBox, iNow(), TimeSpan.Zero);
        Expect("96b a file that changes is looked at again: the notes file is now a genuine sealed file", p3.Handled == 1 && p3.Notes!.Any(n => n.Text == "Verified notes.txt"), string.Join(" | ", p3.Notes ?? []));

        // a file still being written is left until it has sat still
        var iFresh = Tampered(SealedAt(Path.Combine(iWatch, "just saved.pdf")));
        var pBusy = Boxes.RunCheckBoxOnce(iHome, iBox, Time.Now(), TimeSpan.FromSeconds(60));
        Expect("96c a file saved a moment ago is left alone until it has sat still, and is not remembered yet", pBusy.Waiting >= 1 && pBusy.Problems == 0 && File.Exists(iFresh)
            && !((JsonObject)JsonNode.Parse(File.ReadAllText(iSeenPath))!).ContainsKey(iFresh));
        var pLater = Boxes.RunCheckBoxOnce(iHome, iBox, iNow(), TimeSpan.Zero);
        Expect("96d ...then it is judged", pLater.Problems == 1 && !File.Exists(iFresh) && File.Exists(Path.Combine(iRej, "just saved.pdf")));

        // the loop can skip the watched folders on some passes
        var iSkipped = Tampered(SealedAt(Path.Combine(iWatch, "skipped pass.pdf")));
        var pSkip = Boxes.RunCheckBoxOnce(iHome, iBox, iNow(), TimeSpan.Zero, scanWatched: false);
        Expect("96e a pass that skips the watched folders leaves them alone", pSkip.Problems == 0 && File.Exists(iSkipped));
        Boxes.RunCheckBoxOnce(iHome, iBox, iNow(), TimeSpan.Zero);
        Expect("96f ...and the next full pass judges the file", !File.Exists(iSkipped));

        // cannot read: left, warned once, tried again later
        if (!OperatingSystem.IsWindows())
        {
            var iLocked = SealedAt(Path.Combine(iWatch, "Locked.pdf"));
            File.SetUnixFileMode(iLocked, UnixFileMode.None);
            try
            {
                var pLock1 = Boxes.RunCheckBoxOnce(iHome, iBox, iNow(), TimeSpan.Zero);
                var pLock2 = Boxes.RunCheckBoxOnce(iHome, iBox, iNow(), TimeSpan.Zero);
                Expect("97 a sealed file that cannot be read is left in place and warned about once", File.Exists(iLocked) && pLock1.Notes!.Count(n => n.Alert && n.Text.Contains("Locked.pdf")) == 1 && (pLock2.Notes?.Count ?? 0) == 0, $"{string.Join(" | ", pLock1.Notes ?? [])} then {pLock2.Notes?.Count}");
            }
            finally { File.SetUnixFileMode(iLocked, UnixFileMode.UserRead | UnixFileMode.UserWrite); }
            var pLock3 = Boxes.RunCheckBoxOnce(iHome, iBox, Time.Now().AddMinutes(11), TimeSpan.Zero);
            Expect("97b once it can be read it is checked on the next try", pLock3.Notes!.Any(n => n.Text == "Verified Locked.pdf"), string.Join(" | ", pLock3.Notes ?? []));
        }

        // cannot confirm: the company's list ran out. Left in place, warned once, judged when a new list arrives.
        var iArrival = SealedAt(Path.Combine(iWatch, "New arrival.pdf"));
        var iFuture = Time.Now().AddDays(60);
        var pCc1 = Boxes.RunCheckBoxOnce(iHome, iBox, iFuture, TimeSpan.Zero);
        var pCc2 = Boxes.RunCheckBoxOnce(iHome, iBox, iFuture, TimeSpan.Zero);
        Expect("98 when the withdrawn list has run out a new sealed file is left in place and warned about once", File.Exists(iArrival) && pCc1.Problems == 0
            && pCc1.Notes!.Count(n => n.Alert && n.Text.StartsWith("Cannot confirm New arrival.pdf")) == 1 && (pCc2.Notes?.Count ?? 0) == 0, string.Join(" | ", pCc1.Notes ?? []));
        Authority.Publish(iHome, iFuture, 30, null);
        var pCc3 = Boxes.RunCheckBoxOnce(iHome, iBox, iFuture, TimeSpan.Zero);
        Expect("98b a new list makes the box look again: the file is now confirmed", pCc3.Notes!.Count == 1 && pCc3.Notes[0].Text == "Verified New arrival.pdf", string.Join(" | ", pCc3.Notes ?? []));

        // a withdrawal reaches files that were fine when they arrived
        var iBefore = Directory.GetFiles(iWatch).Where(f => !f.EndsWith(".crdownload") && !Path.GetFileName(f).StartsWith('.') && !Path.GetFileName(f).StartsWith("link")).Count();
        Authority.Revoke(iHome, "Marketing Department", null, "laptop lost", 30, now);
        var pRev = Boxes.RunCheckBoxOnce(iHome, iBox, iNow(), TimeSpan.Zero);
        Expect("99 when IT withdraws the department, sealed files that were fine are moved to Rejected and say why", pRev.Problems == iBefore && Directory.GetFiles(iWatch).All(f => !f.EndsWith(".pdf") || Path.GetFileName(f) is ".hidden.pdf" or "link.pdf")
            && File.ReadAllText(Path.Combine(iRej, "Listing photo.pdf.why.txt")).Contains("laptop lost"), $"problems {pRev.Problems} of {iBefore}; left {string.Join(", ", Directory.GetFiles(iWatch).Select(Path.GetFileName))}");
        Expect("99b downloads that have sat still for 60 days are judged like any file and refused, not trusted for their name", File.Exists(Path.Combine(iRej, "still arriving.crdownload")) && File.Exists(Path.Combine(iRej, ".hidden.pdf")));
        var iSeenAfter = (JsonObject)JsonNode.Parse(File.ReadAllText(iSeenPath))!;
        Expect("99c files that have gone are forgotten", !iSeenAfter.ContainsKey(iGenuine) && !iSeenAfter.ContainsKey(iArrival));
    }
    finally { Checker.AfterHashHook = null; }

    // a check that cannot run judges nothing and says so once
    var tBox = Path.Combine(tempRoot, "inspect check box broken");
    var tWatch = Path.Combine(tempRoot, "watched broken");
    Directory.CreateDirectory(tWatch);
    Boxes.SetupCheckBox(tBox, Path.Combine(tempRoot, "no trust folder here"), [], null, [tWatch], "all");
    var tFile = Tampered(Seal(doc, iDept, Path.Combine(tWatch, "waiting.pdf")));
    File.WriteAllText(Path.Combine(tWatch, "ordinary.txt"), "x");
    var tp1 = Boxes.RunCheckBoxOnce(iHome, tBox, Time.Now().AddSeconds(10), TimeSpan.Zero);
    var tp2 = Boxes.RunCheckBoxOnce(iHome, tBox, Time.Now().AddSeconds(10), TimeSpan.Zero);
    Expect("100 without a usable trust folder a sealed file in a watched folder is not judged, and the box says so once",
        File.Exists(tFile) && tp1.Problems == 0 && tp1.Notes!.Count(n => n.Alert && n.Text.StartsWith("The check cannot run")) == 1 && (tp2.Notes?.Count ?? 0) == 0
        && File.ReadAllText(Path.Combine(tBox, "log.txt")).Split("CANNOT CHECK").Length == 2, string.Join(" | ", tp1.Notes ?? []));
    Expect("100b the status line says the check cannot run", File.ReadAllText(Path.Combine(tBox, "status.txt")).StartsWith("The check cannot run"));

    // folders that are missing right now (an unplugged drive) are skipped without fuss
    var mBox = Path.Combine(tempRoot, "inspect check box missing");
    var mWatch = Path.Combine(tempRoot, "watched then gone");
    Directory.CreateDirectory(mWatch);
    Boxes.SetupCheckBox(mBox, iHome.Trust, [], null, [mWatch], "all");
    Directory.Delete(mWatch);
    var mp = Boxes.RunCheckBoxOnce(iHome, mBox, Time.Now().AddSeconds(10), TimeSpan.Zero);
    Expect("100c a watched folder that is not there is skipped quietly", mp.Handled == 0 && mp.Problems == 0 && (mp.Notes?.Count ?? 0) == 0);

    // the check box never judges its own folders
    var sBox = Path.Combine(tempRoot, "inspect check box self");
    Boxes.SetupCheckBox(sBox, iHome.Trust, [], null, null, "all");
    Expect("100d a box cannot be told to watch its own folders", Throws<SealException>(() => Boxes.SetupCheckBox(sBox, iHome.Trust, [], null, [Path.Combine(sBox, "Verified")]), "own folders"));
    Expect("100e nor a folder that is not there", Throws<SealException>(() => Boxes.SetupCheckBox(sBox, iHome.Trust, [], null, [Path.Combine(tempRoot, "never made")]), "cannot find"));
    // a folder that contains the box: the box's own files are skipped
    var wholeWatch = Path.Combine(tempRoot, "watch the parent");
    var wholeBox = Path.Combine(wholeWatch, "Check box");
    Directory.CreateDirectory(wholeWatch);
    Boxes.SetupCheckBox(wholeBox, iHome.Trust, [], null, [wholeWatch], "all");
    Tampered(Seal(doc, iDept, Path.Combine(wholeBox, "Incoming", "arrived bad.pdf")));
    var wholeP = Boxes.RunCheckBoxOnce(iHome, wholeBox, Time.Now().AddSeconds(10), TimeSpan.Zero);
    Expect("100f when the watched folder holds the box, the box's own folders are not judged twice", wholeP.Problems == 1 && File.Exists(Path.Combine(wholeBox, "Rejected", "arrived bad.pdf"))
        && !Directory.GetFiles(Path.Combine(wholeBox, "Rejected"), "*.why.txt").Any(f => File.ReadAllText(f).Contains("watched")));

    // through the command line
    var cWatch = Path.Combine(tempRoot, "watched by command line");
    Directory.CreateDirectory(cWatch);
    var cBox = Path.Combine(tempRoot, "cli inspect box");
    var cWatch2 = Path.Combine(tempRoot, "watched by command line two");
    Directory.CreateDirectory(cWatch2);
    var cSetup = Cli("check-box", "setup", "--folder", cBox, "--trust", iHome.Trust, "--also-watch", cWatch, "--also-watch", cWatch2, "--home", iHome.Root);
    var cJson = (JsonObject)JsonNode.Parse(File.ReadAllText(Path.Combine(cBox, "settings.json")))!;
    Expect("101 --also-watch can be given more than once", cSetup.Code == 0 && cJson["also_watch"]!.AsArray().Count == 2, cSetup.Err);
    Cli("check-box", "setup", "--folder", cBox, "--home", iHome.Root);
    Expect("101b running setup again without the option keeps the folders and the pinned authority", ((JsonObject)JsonNode.Parse(File.ReadAllText(Path.Combine(cBox, "settings.json")))!)["also_watch"]!.AsArray().Count == 2);
    Tampered(Seal(doc, iDept, Path.Combine(cWatch, "cli bad.pdf")));
    var cOnce = Cli("check-box", "run", "--folder", cBox, "--once", "--settle", "0", "--home", iHome.Root);
    Expect("101c a single run looks at the watched folders, prints what it found and returns 1 for a bad file", cOnce.Code == 1 && cOnce.Out.Contains("Look at this: Do not open cli bad.pdf") && File.Exists(Path.Combine(cBox, "Rejected", "cli bad.pdf")), cOnce.Out + cOnce.Err);
    Expect("101d --also-watch with a folder that is not there is refused", Cli("check-box", "setup", "--folder", cBox, "--also-watch", Path.Combine(tempRoot, "never made"), "--home", iHome.Root).Code == 2);
}

// ===================================================================================================
// One command sets up Downloads watching; running it again must never forget who to trust; uninstall takes it all away.
// ===================================================================================================
{
    var uIt = new Home(Path.Combine(tempRoot, "u-it-home"));
    var uDeptRoot = Path.Combine(tempRoot, "u-dept-home");
    var uDept = new Home(uDeptRoot);
    var uShare = Path.Combine(tempRoot, "u company share");
    var uBoxes = Path.Combine(tempRoot, "u boxes");
    var uDownloads = Environment.GetEnvironmentVariable("SONSETSEAL_DOWNLOADS")!;
    var uExtra = Path.Combine(tempRoot, "u shared drive");
    Directory.CreateDirectory(uDownloads);
    Directory.CreateDirectory(uExtra);
    Authority.Init(uIt, "Example Property Group", "IT Department", 10, 30, now);
    Cli("authority", "share-setup", "--share", uShare, "--home", uIt.Root);
    var uPinGiven = Crypto.Sha256Hex(X509Certificate2.CreateFromPem(File.ReadAllText(uIt.CaPem)));
    string[] SetupArgs(params string[] more) => [.. new[] { "setup", "--share", uShare, "--department", "Marketing Department", "--made-for", "Leasing team", "--box-folder", uBoxes, "--key-file", "--no-start", "--home", uDeptRoot }, .. more];
    var uRun = Cli(SetupArgs("--pin-root", uPinGiven, "--also-watch", uExtra, "--notify", "problems"));
    var uCheckBox = Path.Combine(uBoxes, "Check box");
    var uSealBox = Path.Combine(uBoxes, "Seal box");
    JsonObject UCheck() => (JsonObject)JsonNode.Parse(File.ReadAllText(Path.Combine(uCheckBox, "settings.json")))!;
    var uWatched = UCheck()["also_watch"]!.AsArray().Select(w => w!.GetValue<string>()).ToList();
    Expect("102 setup watches Downloads and any other folder given, and says so", uRun.Code == 0 && uWatched.Contains(Path.GetFullPath(uDownloads)) && uWatched.Contains(Path.GetFullPath(uExtra)) && uRun.Out.Contains("also watches"), uRun.Out + uRun.Err);
    Expect("102b the message setting reaches both boxes", Boxes.NotifyMode(uCheckBox) == "problems" && Boxes.NotifyMode(uSealBox) == "problems" && uRun.Out.Contains("only when something needs a look"));
    var uSealItem = Boxes.LoginItemTarget("seal-box", uSealBox);
    var uCheckItem = Boxes.LoginItemTarget("check-box", uCheckBox);
    Expect("102c both login items were written (not started: --no-start)", File.Exists(uSealItem.Path) && File.Exists(uCheckItem.Path) && uRun.Out.Contains("will start at the next login"), uRun.Out);

    var uPin = UCheck()["pin_roots"]!.AsArray().Select(p => p!.GetValue<string>()).ToList();
    // someone puts their own authority on the share, then setup is run again
    File.Copy(Path.Combine(impostor.Trust, "ca.pem"), Path.Combine(uShare, "Trust", "ca.pem"), true);
    File.Copy(Path.Combine(impostor.Trust, "revoked.json"), Path.Combine(uShare, "Trust", "revoked.json"), true);
    var uAgain = Cli(SetupArgs());
    var uPinAfter = UCheck()["pin_roots"]!.AsArray().Select(p => p!.GetValue<string>()).ToList();
    Expect("103 running setup again never forgets the pinned authority, even if the share now holds another one", uAgain.Code == 0 && uPin.Count == 1 && uPinAfter.SequenceEqual(uPin), string.Join(",", uPinAfter));
    Expect("103b ...and running it again keeps the other folders and the message setting", UCheck()["also_watch"]!.AsArray().Count == 2 && Boxes.NotifyMode(uCheckBox) == "problems");
    var uNoDl = Cli(SetupArgs("--no-downloads"));
    var uWatchedNoDl = UCheck()["also_watch"]!.AsArray().Select(w => w!.GetValue<string>()).ToList();
    Expect("103c --no-downloads stops watching Downloads and keeps the rest", uNoDl.Code == 0 && !uWatchedNoDl.Contains(Path.GetFullPath(uDownloads)) && uWatchedNoDl.Contains(Path.GetFullPath(uExtra)), string.Join(",", uWatchedNoDl));
    Expect("103d a folder inside the box cannot be watched through setup either", Cli(SetupArgs("--also-watch", Path.Combine(uCheckBox, "Verified"))).Code == 2);
    Expect("103e nor a folder that is not there", Cli(SetupArgs("--also-watch", Path.Combine(tempRoot, "never made"))).Code == 2);

    // uninstall: login items and key go, every file stays
    File.WriteAllText(Path.Combine(uSealBox, "Done", "keep one.txt"), "mine");
    File.WriteAllText(Path.Combine(uCheckBox, "Verified", "keep two.txt"), "mine too");
    File.WriteAllText(Path.Combine(uSealBox, "Drop here", "not sealed yet.txt"), "waiting");
    File.WriteAllText(Path.Combine(uExtra, "keep three.txt"), "also mine");
    var uOut = Cli("uninstall", "--box-folder", uBoxes, "--home", uDeptRoot);
    Expect("104 uninstall removes both login items", uOut.Code == 0 && !File.Exists(uSealItem.Path) && !File.Exists(uCheckItem.Path) && uOut.Out.Contains("Removed the login item for the seal box") && uOut.Out.Contains("Removed the login item for the check box"), uOut.Out + uOut.Err);
    Expect("104b ...and the department's key and certificate", !Department.Exists(uDept, "Marketing Department") && uOut.Out.Contains("Removed the department's key"), uOut.Out);
    Expect("104c ...and leaves every file where it was", File.ReadAllText(Path.Combine(uSealBox, "Done", "keep one.txt")) == "mine" && File.ReadAllText(Path.Combine(uCheckBox, "Verified", "keep two.txt")) == "mine too"
        && File.Exists(Path.Combine(uSealBox, "Drop here", "not sealed yet.txt")) && File.Exists(Path.Combine(uExtra, "keep three.txt")) && uOut.Out.Contains("Your files were not touched"));
    var uTwice = Cli("uninstall", "--box-folder", uBoxes, "--home", uDeptRoot);
    Expect("104d uninstall twice is harmless and says there is nothing left", uTwice.Code == 0 && uTwice.Out.Contains("had no login item") && uTwice.Out.Contains("No department key was found"), uTwice.Out + uTwice.Err);
    var uEmpty = Cli("uninstall", "--box-folder", Path.Combine(tempRoot, "never installed here"), "--home", Path.Combine(tempRoot, "never installed home"));
    Expect("104e uninstall on a computer where nothing was installed is harmless", uEmpty.Code == 0 && uEmpty.Out.Contains("No department key was found"), uEmpty.Out + uEmpty.Err);
    Expect("104f the settings folder is kept and the person is told where it is", uOut.Out.Contains(uDept.Root) && Directory.Exists(uDept.Root));
}

// ===================================================================================================
// Login items: a name that is unique for each folder, install and removal that leave nothing behind.
// ===================================================================================================
{
    var lA = Boxes.LoginItemTarget("seal-box", Path.Combine(tempRoot, "one", "Seal box"));
    var lB = Boxes.LoginItemTarget("seal-box", Path.Combine(tempRoot, "two", "Seal box"));
    var lA2 = Boxes.LoginItemTarget("seal-box", Path.Combine(tempRoot, "one", "Seal box") + Path.DirectorySeparatorChar);
    Expect("105 two folders with the same name get different login item names, the same folder always the same", lA.Label != lB.Label && lA.Path != lB.Path && lA == lA2, $"{lA.Label} / {lB.Label}");
    if (OperatingSystem.IsMacOS())
        Expect("105b the Mac label names the program, the box, the folder and carries 8 letters or digits of its path", System.Text.RegularExpressions.Regex.IsMatch(lA.Label, @"^ca\.sonset\.sealtool\.seal-box\.seal-box\.[0-9a-f]{8}$") && lA.Path.EndsWith(lA.Label + ".plist"), lA.Label);
    var lOdd = Boxes.LoginItemTarget("check-box", Path.Combine(tempRoot, "日本語"));
    Expect("105c a folder with no ASCII letters in its name still gets a name", lOdd.Label.Contains(".box.") || lOdd.Label.Contains(" box "), lOdd.Label);

    var lHome = Path.Combine(tempRoot, "l-home");
    var lFolder = Path.Combine(tempRoot, "l boxes", "Check box");
    var lInstall = Boxes.InstallAutostart("check-box", lFolder, lHome, startNow: false);
    var lItem = Boxes.LoginItemFor("check-box", lFolder, lHome);
    Expect("106 installing writes the login item and says it starts at the next login", File.Exists(lItem.Path) && lInstall.Contains("will start at the next login") && File.ReadAllText(lItem.Path) == lItem.Text);
    if (OperatingSystem.IsMacOS())
    {
        using var lint = Process.Start(new ProcessStartInfo("/usr/bin/plutil", ["-lint", lItem.Path]) { RedirectStandardOutput = true, RedirectStandardError = true })!;
        var lintOut = lint.StandardOutput.ReadToEnd() + lint.StandardError.ReadToEnd();
        lint.WaitForExit();
        Expect("106b the Mac login item is a valid property list that restarts the box and logs to the box folder", lint.ExitCode == 0 && lItem.Text.Contains("<key>KeepAlive</key><true/>") && lItem.Text.Contains("<key>RunAtLoad</key><true/>")
            && lItem.Text.Contains(Path.Combine(lFolder, "launchd.log")) && lItem.Text.Contains("<string>check-box</string>") && lItem.Text.Contains("<string>run</string>") && lItem.Text.Contains("<string>" + lHome + "</string>"), lintOut);
    }
    var lRemove = Boxes.RemoveAutostart("check-box", lFolder);
    Expect("106c removing takes the login item away and says so", !File.Exists(lItem.Path) && lRemove.Contains("Removed the login item for the check box"), lRemove);
    Expect("106d removing again says there was nothing", Boxes.RemoveAutostart("check-box", lFolder).Contains("had no login item"));
    var lCli = Cli("seal-box", "autostart", "--folder", lFolder, "--home", lHome);
    Expect("106e the command line only shows what would be written, and says how to install and remove", lCli.Code == 0 && lCli.Out.Contains("--install") && lCli.Out.Contains("--remove") && !File.Exists(Boxes.LoginItemTarget("seal-box", lFolder).Path));
    Boxes.InstallAutostart("seal-box", lFolder, lHome, startNow: false);
    var lCliRemove = Cli("seal-box", "autostart", "--folder", lFolder, "--remove", "--home", lHome);
    Expect("106f 'autostart --remove' removes it", lCliRemove.Code == 0 && lCliRemove.Out.Contains("Removed the login item") && !File.Exists(Boxes.LoginItemTarget("seal-box", lFolder).Path), lCliRemove.Out + lCliRemove.Err);
    Expect("106g --install and --remove together are refused", Cli("seal-box", "autostart", "--folder", lFolder, "--install", "--remove", "--home", lHome).Code == 2);

    // finding every login item that belongs to one home folder
    var lHomeB = Path.Combine(tempRoot, "l-home-other");
    Boxes.InstallAutostart("seal-box", Path.Combine(tempRoot, "l boxes", "Seal box"), lHome, startNow: false);
    Boxes.InstallAutostart("check-box", Path.Combine(tempRoot, "l boxes", "Check box"), lHome, startNow: false);
    Boxes.InstallAutostart("seal-box", Path.Combine(tempRoot, "l others", "Seal box"), lHomeB, startNow: false);
    if (OperatingSystem.IsMacOS())
    {
        var oldStyle = Path.Combine(Boxes.LoginItemsFolderOverride!, "ca.sonset.sealtool.seal-box.old-style.plist");
        File.WriteAllText(oldStyle, Boxes.MacLaunchAgent("ca.sonset.sealtool.seal-box.old-style", "/x/sonsetseal", ["seal-box", "run", "--folder", "/old/Seal box", "--home", lHome]));
    }
    var lFound = Boxes.LoginItemsFor(lHome);
    Expect("107 every login item for one home is found (older style names too) and none for another home", lFound.Count == (OperatingSystem.IsMacOS() ? 3 : 2) && lFound.All(f => File.ReadAllText(f.Path).Contains(lHome)) && !lFound.Any(f => File.ReadAllText(f.Path).Contains(lHomeB)), string.Join(", ", lFound.Select(f => f.Label)));
    foreach (var f in lFound) Boxes.RemoveLoginItemAt(f.Label, f.Path);
    Expect("107b removing those leaves the other home's login item", Boxes.LoginItemsFor(lHome).Count == 0 && Boxes.LoginItemsFor(lHomeB).Count == 1);
    foreach (var f in Boxes.LoginItemsFor(lHomeB)) Boxes.RemoveLoginItemAt(f.Label, f.Path);

    // one copy of a box at a time
    var lockFolder = Path.Combine(tempRoot, "lock me");
    var first = Boxes.BoxLock.TryTake(lockFolder);
    var second = Boxes.BoxLock.TryTake(lockFolder);
    Expect("108 a second copy of the same box cannot take it, and the first one's pid is on file", first != null && second == null && File.ReadAllText(Boxes.BoxLock.PidFile(lockFolder)) == Environment.ProcessId.ToString());
    first!.Dispose();
    var third = Boxes.BoxLock.TryTake(lockFolder);
    Expect("108b once the first stops, another can take over", third != null);
    third!.Dispose();
    Expect("108c the pid file goes away when the box stops", !File.Exists(Boxes.BoxLock.PidFile(lockFolder)));
}

// ===================================================================================================
// The review before the public release: every hole it found became a test.
// ===================================================================================================
{
    var hHome = NewCompany("hardening");
    var hDept = MakeDepartment(hHome, "Marketing Department");
    using var hCa = X509Certificate2.CreateFromPem(File.ReadAllText(hHome.CaPem));
    var hPin = Crypto.Sha256Hex(hCa);
    var hDir = Path.Combine(tempRoot, "hardening-files"); Directory.CreateDirectory(hDir);
    var hDoc = Path.Combine(hDir, "paper.txt"); File.WriteAllText(hDoc, "paper bytes");
    var hSealed = Seal(hDoc, hDept);
    var hGenuine = File.ReadAllBytes(hSealed);
    string NewCheckBox(string name, params string[] pins) { var b = Path.Combine(tempRoot, name); Boxes.SetupCheckBox(b, hHome.Trust, pins); return b; }

    // ----- code run from a file name (Windows pop up)
    var evil = "x’, ’Info’); Start-Process calc; (‘.pdf";
    var balloon = Notify.WindowsBalloon("Sonset seal", "Do not open " + evil);
    Expect("110 the Windows pop up script is fixed text: a file name travels as data and never becomes code",
        balloon.ArgumentList[^1] == Notify.BalloonScript && !string.Join(" ", balloon.ArgumentList).Contains("calc") && balloon.Environment["SONSETSEAL_MESSAGE"] == "Do not open " + evil
        && !Notify.BalloonScript.Contains("calc") && balloon.FileName.EndsWith("powershell.exe"), string.Join(" | ", balloon.ArgumentList));

    // ----- a pin that is not a pin
    Expect("110b an empty pin is an error, not 'no pin'", Throws<SealException>(() => TrustPolicy.FromFolder(hHome.Trust, now, [""]), "64 hexadecimal"));
    Expect("110c a pin that is not hex is an error", Throws<SealException>(() => TrustPolicy.FromFolder(hHome.Trust, now, ["not a fingerprint"]), "64 hexadecimal"));
    Expect("110d the system mode refuses an empty pin too", Throws<SealException>(() => TrustPolicy.FromSystem([""]), "64 hexadecimal"));

    // ----- the memory of list numbers: damaged is not the same as off
    var seenPath = Path.Combine(hDir, "seen-lists.json");
    File.WriteAllText(seenPath, "{ this is not json");
    var healed = TrustPolicy.FromFolder(hHome.Trust, now, null, seenPath);
    Expect("110e a damaged memory of list numbers is kept aside and rebuilt, not left switched off",
        healed.Problem == null && File.Exists(seenPath + ".damaged") && ((JsonObject)JsonNode.Parse(File.ReadAllText(seenPath))!)[hPin] != null);
    var olderTrust = Path.Combine(tempRoot, "older-trust"); Directory.CreateDirectory(olderTrust);
    File.Copy(hHome.CaPem, Path.Combine(olderTrust, "ca.pem")); File.Copy(hHome.RevokedList, Path.Combine(olderTrust, "revoked.json"));
    Authority.Publish(hHome, now, 30, null);
    TrustPolicy.FromFolder(hHome.Trust, now, null, seenPath);
    Expect("110f an older (but genuine) list is refused once a newer one was seen", TrustPolicy.FromFolder(olderTrust, now, null, seenPath).Problem?.Contains("older") == true);
    var atomicPath = Path.Combine(hDir, "atomic.txt");
    Files.WriteAtomic(atomicPath, "one"); Files.WriteAtomic(atomicPath, "two");
    Expect("110g replacing a file in one step leaves no temporary files", File.ReadAllText(atomicPath) == "two" && Directory.GetFiles(hDir, ".*.tmp").Length == 0);

    // ----- links and named pipes
    if (!OperatingSystem.IsWindows())
    {
        var outside = Path.Combine(tempRoot, "hard-outside"); Directory.CreateDirectory(outside);
        var secret = Path.Combine(outside, "secret.txt"); File.WriteAllText(secret, "secret");
        var walkRoot = Path.Combine(tempRoot, "hard-walk"); Directory.CreateDirectory(Path.Combine(walkRoot, "real")); File.WriteAllText(Path.Combine(walkRoot, "real", "b.txt"), "b");
        File.CreateSymbolicLink(Path.Combine(walkRoot, "linkdir"), outside);
        File.CreateSymbolicLink(Path.Combine(walkRoot, "linkfile.txt"), secret);
        var walked = Files.Walk(walkRoot).Select(f => Path.GetRelativePath(walkRoot, f)).OrderBy(x => x, StringComparer.Ordinal).ToList();
        Expect("110h a link to a folder is not followed, a link to a file is listed so it can be refused",
            walked.SequenceEqual([ "linkfile.txt", Path.Combine("real", "b.txt") ]), string.Join(", ", walked));

        var lBox = NewCheckBox("link-check-box", hPin);
        File.CreateSymbolicLink(Path.Combine(lBox, "Incoming", "link to paper.txt"), hSealed);
        File.CreateSymbolicLink(Path.Combine(lBox, "Incoming", "folder link"), outside);
        var lr = Boxes.RunCheckBoxOnce(hHome, lBox, Time.Now().AddSeconds(10), TimeSpan.Zero);
        Expect("110i a link in Incoming is rejected as a link; what it points at and a linked folder are left alone",
            lr.Handled == 0 && lr.Problems == 1 && File.Exists(hSealed) && File.Exists(secret) && File.Exists(Path.Combine(lBox, "Rejected", "link to paper.txt"))
            && File.ReadAllText(Path.Combine(lBox, "Rejected", "link to paper.txt.why.txt")).Contains("is a link"), $"{lr}");

        var sBoxL = Path.Combine(tempRoot, "link-seal-box");
        Boxes.SetupSealBox(sBoxL, new Boxes.SealDefaults("Marketing Department", "Marketing Department", "Leasing team", null, null, null, null));
        File.CreateSymbolicLink(Path.Combine(sBoxL, "Drop here", "linked.txt"), secret);
        var sr = Boxes.RunSealBoxOnce(hHome, sBoxL, Time.Now().AddSeconds(10), TimeSpan.Zero);
        Expect("110j a link in Drop here is refused, never sealed, and its target stays where it is",
            sr.Problems == 1 && sr.Handled == 0 && File.Exists(secret) && Directory.GetFiles(Path.Combine(sBoxL, "Sealed")).Length == 0, $"{sr}");

        Files.OpenTimeout = TimeSpan.FromMilliseconds(400);
        try
        {
            var fBox = NewCheckBox("pipe-check-box", hPin);
            Sh($"mkfifo '{Path.Combine(fBox, "Incoming", "pipe.pdf")}'");
            File.WriteAllBytes(Path.Combine(fBox, "Incoming", "good.txt"), hGenuine);
            var pipeClock = Stopwatch.StartNew();
            var fr = Boxes.RunCheckBoxOnce(hHome, fBox, Time.Now().AddSeconds(10), TimeSpan.Zero);
            var firstPass = pipeClock.Elapsed.TotalSeconds;
            pipeClock.Restart();
            Boxes.RunCheckBoxOnce(hHome, fBox, Time.Now().AddSeconds(20), TimeSpan.Zero);
            Expect("110k a named pipe in Incoming cannot freeze the box: it is rejected, the good file is still verified, and the next pass is instant",
                fr.Handled == 1 && fr.Problems == 1 && File.Exists(Path.Combine(fBox, "Verified", "good.txt")) && firstPass < 10 && pipeClock.Elapsed.TotalSeconds < 2
                && File.ReadAllText(Path.Combine(fBox, "Rejected", "pipe.pdf.why.txt")).Contains("did not open in time"), $"{fr} {firstPass:F1}s then {pipeClock.Elapsed.TotalSeconds:F1}s");
        }
        finally { Files.OpenTimeout = TimeSpan.FromSeconds(5); }
    }

    // ----- the file that is checked is the file that is kept
    {
        var rBox = NewCheckBox("race-check-box", hPin);
        var keepDate = new DateTime(2025, 1, 2, 3, 4, 5, DateTimeKind.Utc);
        File.WriteAllBytes(Path.Combine(rBox, "Incoming", "paper.txt"), hGenuine);
        File.SetLastWriteTimeUtc(Path.Combine(rBox, "Incoming", "paper.txt"), keepDate);
        var newer = Encoding.ASCII.GetBytes("a newer version that nobody has checked");
        // A newer file arrives under the same name at the worst moment: right after the box took the first one in.
        Boxes.AfterTakeHook = original => { Boxes.AfterTakeHook = null; File.WriteAllBytes(original, newer); };
        Boxes.BoxReport rr;
        try { rr = Boxes.RunCheckBoxOnce(hHome, rBox, Time.Now().AddSeconds(10), TimeSpan.Zero); }
        finally { Boxes.AfterTakeHook = null; }
        Expect("110l the file that was checked is the one that moves on; a newer file with the same name is left for the next look, not deleted",
            rr.Handled == 1 && File.ReadAllBytes(Path.Combine(rBox, "Verified", "paper.txt")).SequenceEqual(hGenuine) && File.ReadAllBytes(Path.Combine(rBox, "Incoming", "paper.txt")).SequenceEqual(newer)
            && !Directory.EnumerateFileSystemEntries(Path.Combine(rBox, ".working")).Any(), $"{rr}");
        Expect("110la a verified file keeps its modification date (it was moved, not copied)", File.GetLastWriteTimeUtc(Path.Combine(rBox, "Verified", "paper.txt")) == keepDate);
        File.SetLastWriteTimeUtc(Path.Combine(rBox, "Incoming", "paper.txt"), keepDate);
        var rr2 = Boxes.RunCheckBoxOnce(hHome, rBox, Time.Now().AddSeconds(20), TimeSpan.Zero);
        Expect("110lb the newer file is then judged on its own, and refused because it carries no seal", rr2.Problems == 1 && File.Exists(Path.Combine(rBox, "Rejected", "paper.txt")) && !File.Exists(Path.Combine(rBox, "Incoming", "paper.txt")), $"{rr2}");
        if (!OperatingSystem.IsWindows())
            Expect("110m the box's own folders can be opened by this user only", (File.GetUnixFileMode(rBox) & (UnixFileMode.GroupRead | UnixFileMode.OtherRead | UnixFileMode.GroupExecute | UnixFileMode.OtherExecute | UnixFileMode.GroupWrite | UnixFileMode.OtherWrite)) == 0
                && (File.GetUnixFileMode(Path.Combine(rBox, "Verified")) & (UnixFileMode.GroupRead | UnixFileMode.OtherRead)) == 0);

        // a leftover from a pass that was cut short goes back to Incoming, it is never thrown away
        var cutBox = NewCheckBox("cut-check-box", hPin);
        Directory.CreateDirectory(Path.Combine(cutBox, ".working", "abc123"));
        File.WriteAllBytes(Path.Combine(cutBox, ".working", "abc123", "half way.txt"), hGenuine);
        var cutRun = Boxes.RunCheckBoxOnce(hHome, cutBox, Time.Now().AddSeconds(10), TimeSpan.Zero);
        Expect("110ld a file left in the box's private folder by a cut short pass is recovered and checked, not lost", cutRun.Handled == 1 && File.Exists(Path.Combine(cutBox, "Verified", "half way.txt")), $"{cutRun}");

        if (!OperatingSystem.IsWindows())
        {
            // a file the box cannot take out of its folder is reported once and costs nothing: no copy is made, nothing piles up
            var lockedBox = NewCheckBox("locked-check-box", hPin);
            var lockedDir = Path.Combine(lockedBox, "Incoming", "from a zip"); Directory.CreateDirectory(lockedDir);
            File.WriteAllBytes(Path.Combine(lockedDir, "stuck.txt"), hGenuine);
            File.SetUnixFileMode(lockedDir, UnixFileMode.UserRead | UnixFileMode.UserExecute);
            try
            {
                var l1 = Boxes.RunCheckBoxOnce(hHome, lockedBox, Time.Now().AddSeconds(10), TimeSpan.Zero);
                var afterOne = $"mode {File.GetUnixFileMode(lockedDir)} stuckThere={File.Exists(Path.Combine(lockedDir, "stuck.txt"))} verified={Directory.GetFiles(Path.Combine(lockedBox, "Verified")).Length}";
                var l2 = Boxes.RunCheckBoxOnce(hHome, lockedBox, Time.Now().AddSeconds(20), TimeSpan.Zero);
                afterOne += $" | after two: stuckThere={File.Exists(Path.Combine(lockedDir, "stuck.txt"))} verified={Directory.GetFiles(Path.Combine(lockedBox, "Verified")).Length} working={string.Join(",", Directory.EnumerateFileSystemEntries(Path.Combine(lockedBox, ".working"), "*", SearchOption.AllDirectories).Select(Path.GetFileName))}";
                Expect("110le a file in a folder the box cannot change is never copied again and again: Verified stays empty, the file stays, one warning",
                    l1.Handled == 0 && l2.Handled == 0 && Directory.GetFiles(Path.Combine(lockedBox, "Verified")).Length == 0 && File.Exists(Path.Combine(lockedDir, "stuck.txt"))
                    && File.ReadAllText(Path.Combine(lockedBox, "log.txt")).Split("STUCK").Length == 2, $"{l1} {l2} {afterOne}");
            }
            finally { File.SetUnixFileMode(lockedDir, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute); }
        }
    }

    // ----- a call that is only slow is not blacklisted for ever
    {
        Files.OpenTimeout = TimeSpan.FromMilliseconds(100);
        try
        {
            var slowPath = "slow-test-path";
            var first = Files.RunWithin(slowPath, () => { Thread.Sleep(400); return 1; }, out _);
            var meanwhile = Files.RunWithin(slowPath, () => 2, out _);
            Thread.Sleep(600);
            var later = Files.RunWithin(slowPath, () => 3, out var value);
            Expect("110lf a slow call times out once, is not started again while it is stuck, and is tried afresh once it has ended", !first && !meanwhile && later && value == 3);
        }
        finally { Files.OpenTimeout = TimeSpan.FromSeconds(5); }
    }

    // ----- a list that ran out is not the file's fault
    {
        var eHome = NewCompany("expired-list");
        var eDept = MakeDepartment(eHome, "Marketing Department");
        var eSealed = Seal(hDoc, eDept);
        Authority.Publish(eHome, now.AddDays(-40), 30, null); // issued 40 days ago, good for 30
        var eBox = Path.Combine(tempRoot, "expired-check-box"); Boxes.SetupCheckBox(eBox, eHome.Trust, []);
        File.Copy(eSealed, Path.Combine(eBox, "Incoming", "late.txt"));
        var er = Boxes.RunCheckBoxOnce(eHome, eBox, Time.Now().AddSeconds(10), TimeSpan.Zero);
        Expect("110n a good file is not thrown away because the company's list ran out: it stays in Incoming with a warning",
            er.Handled == 0 && er.Problems == 0 && er.Waiting == 1 && File.Exists(Path.Combine(eBox, "Incoming", "late.txt")) && Directory.GetFiles(Path.Combine(eBox, "Rejected")).Length == 0
            && er.Notes!.Any(n => n.Alert && n.Text.Contains("Cannot confirm")), $"{er}");
        var eBox2 = Path.Combine(tempRoot, "expired-check-box-2"); Boxes.SetupCheckBox(eBox2, eHome.Trust, []);
        File.Copy(eSealed, Path.Combine(eBox2, "Incoming", "late.txt"));
        var takes = 0; Boxes.AfterTakeHook = _ => takes++;
        Boxes.BoxReport er2, er3;
        try
        {
            File.Copy(eSealed, Path.Combine(eBox, "Incoming", "later.txt"));
            Boxes.RunCheckBoxOnce(eHome, eBox, Time.Now().AddSeconds(30), TimeSpan.Zero);   // takes later.txt once and puts it back
            var afterFirst = takes;
            er2 = Boxes.RunCheckBoxOnce(eHome, eBox, Time.Now().AddSeconds(40), TimeSpan.Zero);
            er3 = Boxes.RunCheckBoxOnce(eHome, eBox, Time.Now().AddSeconds(50), TimeSpan.Zero);
            Expect("110na a file that could not be confirmed is not taken in and copied again every pass: it is left alone until it or the company's lists change", afterFirst == 1 && takes == 1 && er3.Waiting == 2, $"takes after first {afterFirst}, in total {takes}, {er3}");
        }
        finally { Boxes.AfterTakeHook = null; }
        var once = Cli("check-box", "run", "--folder", eBox2, "--once", "--settle", "0", "--home", eHome.Root);
        Expect("110o a single run that could not confirm something does not exit as if all was well", once.Code == 1 && once.Out.Contains("Look at this"), once.Out + once.Err);
    }

    // ----- crafted seals never crash the checker
    {
        var craftedEnv = ReadEnvelope(hSealed, out var craftedBody);
        var old = Clone(craftedEnv); ((JsonObject)old["signed"]!)["sealed_at"] = "1500-01-01T00:00:00Z";
        var oldPath = Path.Combine(hDir, "dated 1500.txt"); WriteWith(oldPath, craftedBody, old);
        var oldResult = Full(oldPath, hHome.Trust);
        Expect("110p a seal dated 1500 is refused before it reaches the operating system's certificate code", oldResult.Status == "NOT_TRUSTED" && oldResult.Reason.Contains("before this tool existed"), $"{oldResult.Status}: {oldResult.Reason}");
        var many = Clone(craftedEnv); var pem = (string)craftedEnv["cert"]!; many["chain"] = new JsonArray(Enumerable.Range(0, 9).Select(_ => (JsonNode)JsonValue.Create(pem)!).ToArray());
        var manyPath = Path.Combine(hDir, "long chain.txt"); WriteWith(manyPath, craftedBody, many);
        var manyResult = Full(manyPath, hHome.Trust);
        Expect("110q a seal carrying a very long chain of certificates is refused as damaged", manyResult.Status == "DAMAGED" && manyResult.Reason.Contains("more certificates"), $"{manyResult.Status}: {manyResult.Reason}");
    }
    {
        using var weak = RSA.Create(1024);
        var weakCert = new CertificateRequest("CN=weak", weak, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1).CreateSelfSigned(now.AddDays(-1), now.AddDays(1));
        var data = Encoding.ASCII.GetBytes("data");
        using var strong = RSA.Create(2048);
        var strongCert = new CertificateRequest("CN=strong", strong, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1).CreateSelfSigned(now.AddDays(-1), now.AddDays(1));
        Expect("110r a valid signature from a 1024 bit RSA key is refused, a 2048 bit one is accepted",
            !Crypto.Verify(weakCert, data, weak.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1))
            && Crypto.Verify(strongCert, data, strong.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)));
    }

    {
        var newerEnv = ReadEnvelope(hSealed, out var newerBody);
        var v3 = Clone(newerEnv); ((JsonObject)v3["signed"]!)["v"] = 3;
        var v3Path = Path.Combine(hDir, "version three.txt"); WriteWith(v3Path, newerBody, v3);
        var v3Result = Full(v3Path, hHome.Trust);
        Expect("110rb a seal from a newer version is not called old: it says to update the program", v3Result.Status == "DAMAGED" && v3Result.Reason.Contains("different version") && !v3Result.Reason.Contains("older format"), $"{v3Result.Status}: {v3Result.Reason}");
        var oldEnv = ReadEnvelope(hSealed, out var oldBody);
        var v1 = Clone(oldEnv); ((JsonObject)v1["signed"]!)["v"] = 1;
        var v1Path = Path.Combine(hDir, "version one.txt"); WriteWith(v1Path, oldBody, v1);
        var v1Result = Full(v1Path, hHome.Trust);
        Expect("110ra a seal in the old version 1 format gets a plain refusal, not a pass and not a crash", v1Result.Status == "NOT_TRUSTED" && v1Result.Reason.Contains("older format"), $"{v1Result.Status}: {v1Result.Reason}");
    }

    // ----- the sealer
    Expect("110s the sealer refuses a hidden character the checker would refuse anyway", Throws<SealException>(() => Sealer.Seal(hDoc, hDept, Fields3("Listing​ photo"), Path.Combine(hDir, "zero width.txt")), "hidden"));
    {
        var lBoxName = Path.Combine(tempRoot, "long-name-seal-box");
        Boxes.SetupSealBox(lBoxName, new Boxes.SealDefaults("Marketing Department", "Marketing Department", "Leasing team", null, null, null, null));
        var longName = new string('x', 248) + ".txt";
        File.WriteAllText(Path.Combine(lBoxName, "Drop here", longName), "long");
        File.WriteAllText(Path.Combine(lBoxName, "Drop here", "ok.txt"), "short");
        Boxes.BoxReport lnr;
        try { lnr = Boxes.RunSealBoxOnce(hHome, lBoxName, Time.Now().AddSeconds(10), TimeSpan.Zero); }
        catch (Exception e) { lnr = new Boxes.BoxReport(-1, -1, -1); Console.WriteLine("  threw " + e.GetType().Name + ": " + e.Message); }
        Expect("110t a file name too long to seal goes to Problems and the next file is still sealed", lnr.Handled == 1 && lnr.Problems == 1 && File.Exists(Path.Combine(lBoxName, "Sealed", "ok.sealed.txt")), $"{lnr} drop=[{string.Join('|', Directory.GetFiles(Path.Combine(lBoxName, "Drop here")).Select(f => Path.GetFileName(f).Length))}] problems=[{string.Join('|', Directory.GetFiles(Path.Combine(lBoxName, "Problems")).Select(f => Path.GetFileName(f).Length))}] log={(File.Exists(Path.Combine(lBoxName, "log.txt")) ? File.ReadAllText(Path.Combine(lBoxName, "log.txt")) : "-")}");
        Expect("110u no temporary file is left in Sealed", Directory.GetFiles(Path.Combine(lBoxName, "Sealed"), ".*.part").Length == 0);
    }
    {
        var racePath = Path.Combine(hDir, "grows.bin"); File.WriteAllBytes(racePath, new byte[3_000_000]);
        var sealedGrows = Seal(racePath, hDept);
        Expect("110v what is sealed is what was copied: the sealed copy of a big file checks out", Full(sealedGrows, hHome.Trust).Ok);
    }

    // ----- the loop never exits because of one bad file
    {
        var calls = 0; using var stop = new CancellationTokenSource(); var log = new StringWriter();
        Boxes.RunLoop(() => { calls++; if (calls == 1) throw new InvalidOperationException("boom"); if (calls == 3) stop.Cancel(); return new Boxes.BoxReport(0, 0, 0); }, log, stop.Token, interval: TimeSpan.FromMilliseconds(5));
        Expect("110w an unexpected error inside a pass is logged and the box carries on", calls >= 3 && log.ToString().Contains("Unexpected problem"), log.ToString());
    }

    // ----- trust from the company share
    {
        var tHome = NewCompany("share-trust");
        var tShare = Path.Combine(tempRoot, "share-trust-share");
        Authority.ShareSetup(tHome, tShare);
        using var tCa = X509Certificate2.CreateFromPem(File.ReadAllText(tHome.CaPem));
        var tPin = Crypto.Sha256Hex(tCa);
        Expect("110x a box that takes trust from a share must be given a pin, or be told to trust the first authority", Throws<SealException>(() => Boxes.SetupCheckBox(Path.Combine(tempRoot, "share-box-0"), null, [], tShare), "--pin-root"));
        var tBox = Path.Combine(tempRoot, "share-box-1");
        Boxes.SetupCheckBox(tBox, null, [], tShare, null, null, trustOnFirstUse: true);
        Boxes.SyncTrust(tBox);
        var tSettings = (JsonObject)JsonNode.Parse(File.ReadAllText(Path.Combine(tBox, "settings.json")))!;
        Expect("110y trust on first use, when asked for, copies and pins the authority and says so", File.Exists(Path.Combine(tBox, "trust", "ca.pem"))
            && tSettings["pin_roots"]![0]!.GetValue<string>() == tPin && File.ReadAllText(Path.Combine(tBox, "log.txt")).Contains("AUTHORITY PINNED"));

        var localList = File.ReadAllBytes(Path.Combine(tBox, "trust", "revoked.json"));
        File.Copy(impostor.RevokedList, Path.Combine(tShare, "Trust", "revoked.json"), true);
        Boxes.SyncTrust(tBox);
        Expect("110z a list on the share that the authority did not sign never replaces the good one", File.ReadAllBytes(Path.Combine(tBox, "trust", "revoked.json")).SequenceEqual(localList)
            && File.ReadAllText(Path.Combine(tBox, "log.txt")).Contains("not signed by the authority"));
        File.WriteAllBytes(Path.Combine(tShare, "Trust", "revoked.json"), new byte[2_000_000]);
        Boxes.SyncTrust(tBox);
        Expect("110aa a huge file on the share is not read and the good list stays", File.ReadAllBytes(Path.Combine(tBox, "trust", "revoked.json")).SequenceEqual(localList)
            && File.ReadAllText(Path.Combine(tBox, "log.txt")).Contains("could not be read"));
        Authority.Publish(tHome, now, 30, null);
        var newer = File.ReadAllBytes(Path.Combine(tShare, "Trust", "revoked.json"));
        Boxes.SyncTrust(tBox);
        Expect("110ab a newer list from the real authority does arrive", File.ReadAllBytes(Path.Combine(tBox, "trust", "revoked.json")).SequenceEqual(newer));
        var staleCopy = Path.Combine(tempRoot, "stale-list.json");
        File.WriteAllBytes(staleCopy, localList); // the older list, genuinely signed
        File.Copy(staleCopy, Path.Combine(tShare, "Trust", "revoked.json"), true);
        Boxes.SyncTrust(tBox);
        Expect("110ac a genuine but older list put back on the share does not replace the newer one", File.ReadAllBytes(Path.Combine(tBox, "trust", "revoked.json")).SequenceEqual(newer));
        if (!OperatingSystem.IsWindows())
        {
            var pinnedBox = Path.Combine(tempRoot, "share-box-2"); Boxes.SetupCheckBox(pinnedBox, null, [tPin], tShare);
            File.Delete(Path.Combine(tShare, "Trust", "ca.pem"));
            File.CreateSymbolicLink(Path.Combine(tShare, "Trust", "ca.pem"), tHome.CaPem);
            Boxes.SyncTrust(pinnedBox);
            Expect("110ad a link where the share's certificate should be is not followed", !File.Exists(Path.Combine(pinnedBox, "trust", "ca.pem")) && File.ReadAllText(Path.Combine(pinnedBox, "log.txt")).Contains("could not be read"));
        }
        Expect("110ae a pinned box ignores a different authority on the share", true); // covered by 85
        Expect("110af a share inside the authority's secret key folder is refused", Throws<SealException>(() => Authority.ShareSetup(tHome, tHome.Authority), "secret key") && Throws<SealException>(() => Authority.ShareSetup(tHome, tHome.Root), "secret key"));
    }

    // ----- the certificate that arrives through the share
    {
        var iHome = NewCompany("install-co");
        var iShare = Path.Combine(tempRoot, "install-share");
        Authority.ShareSetup(iHome, iShare);
        using var iCa = X509Certificate2.CreateFromPem(File.ReadAllText(iHome.CaPem));
        var iPin = Crypto.Sha256Hex(iCa);
        var rogue = NewCompany("rogue-install");
        var dHome = new Home(Path.Combine(tempRoot, "install-dept-home"));
        Department.Request(dHome, "Marketing Department", true, now);
        Department.PublishRequest(dHome, "Marketing Department", iShare);
        var csr = File.ReadAllBytes(Path.Combine(dHome.Departments, "marketing-department", "request.csr.pem"));
        var certInShare = Path.Combine(iShare, "Certificates", "marketing-department.pem");
        File.Copy(Authority.SignRequest(rogue, csr, "Marketing Department", 365, now), certInShare);
        var rogueTry = Department.TryInstallFromShare(dHome, "Marketing Department", iShare, [iPin]);
        Expect("111 a certificate from another authority is not installed even though it fits the department's key", !rogueTry.Installed && rogueTry.Problem != null && !Department.HasCertificate(dHome, "Marketing Department"), rogueTry.Problem ?? "");
        File.Copy(Authority.SignRequest(iHome, csr, "Marketing Department", 365, now), certInShare, true);
        Expect("111b with no pin, nothing from the share is trusted", Department.TryInstallFromShare(dHome, "Marketing Department", iShare, []).Problem?.Contains("pinned") == true && !Department.HasCertificate(dHome, "Marketing Department"));
        Expect("111c with the wrong pin, nothing is installed", Department.TryInstallFromShare(dHome, "Marketing Department", iShare, [hPin]).Problem?.Contains("not the one pinned") == true && !Department.HasCertificate(dHome, "Marketing Department"));
        Expect("111d with the right pin the real certificate is installed", Department.TryInstallFromShare(dHome, "Marketing Department", iShare, [iPin]).Installed && Department.HasCertificate(dHome, "Marketing Department"));
    }

    // ----- the second round of review
    {
        // one garbage file on the share must not stop a box
        var gHome = NewCompany("garbage-share");
        var gDept = MakeDepartment(gHome, "Marketing Department");
        var gShare = Path.Combine(tempRoot, "garbage-share-folder");
        Authority.ShareSetup(gHome, gShare);
        using var gCa = X509Certificate2.CreateFromPem(File.ReadAllText(gHome.CaPem));
        var gBox = Path.Combine(tempRoot, "garbage-box"); Boxes.SetupCheckBox(gBox, null, [Crypto.Sha256Hex(gCa)], gShare);
        Boxes.SyncTrust(gBox);
        File.WriteAllText(Path.Combine(gShare, "Trust", "ca.pem"), "x");
        File.WriteAllBytes(Path.Combine(gBox, "Incoming", "good.txt"), File.ReadAllBytes(Seal(hDoc, gDept)));
        Boxes.BoxReport gr;
        try { gr = Boxes.RunCheckBoxOnce(gHome, gBox, Time.Now().AddSeconds(10), TimeSpan.Zero); }
        catch (Exception e) { gr = new Boxes.BoxReport(-1, -1, -1); Console.WriteLine("  threw " + e.GetType().Name + ": " + e.Message); }
        Expect("113 a garbage certificate on the share stops nothing: the box tells the person and still checks files against the trust it has",
            gr.Handled == 1 && gr.Notes!.Any(n => n.Alert && n.Text.Contains("trust could not be updated")), $"{gr} " + string.Join(" | ", gr.Notes ?? []));
        File.Delete(Path.Combine(gShare, "Trust", "ca.pem"));
        Boxes.RunCheckBoxOnce(gHome, gBox, Time.Now().AddSeconds(20), TimeSpan.Zero);
        Expect("113b a missing trust folder on the share is also something the person is told", Boxes.SyncTrust(gBox)?.Contains("no trust folder") == true);

        // a name that says "download" is not a hiding place
        var wBox = Path.Combine(tempRoot, "watch-name-box"); var wDir = Path.Combine(tempRoot, "watch-name-dir"); Directory.CreateDirectory(wDir);
        Boxes.SetupCheckBox(wBox, hHome.Trust, [], null, [wDir]);
        string BadCopy(string name, DateTime written)
        {
            var path = Path.Combine(wDir, name);
            var bytes = File.ReadAllBytes(hSealed); bytes[3] ^= 1; File.WriteAllBytes(path, bytes); File.SetLastWriteTimeUtc(path, written);
            return path;
        }
        var fresh = BadCopy("~Fresh.pdf", DateTime.UtcNow);
        var stale = BadCopy("~Invoice 4417.pdf", DateTime.UtcNow.AddHours(-2));
        var future = BadCopy("Dated 2099.pdf", new DateTime(2099, 1, 1, 0, 0, 0, DateTimeKind.Utc));
        var futurePartial = BadCopy("~Dated 2099.pdf.part", new DateTime(2099, 1, 1, 0, 0, 0, DateTimeKind.Utc));
        var wr = Boxes.RunCheckBoxOnce(hHome, wBox, Time.Now().AddSeconds(10), TimeSpan.Zero);
        Expect("113c a tampered sealed file called ~Invoice.pdf is judged once it has sat still, and so are ones dated far in the future; one that is still arriving waits",
            File.Exists(fresh) && !File.Exists(stale) && !File.Exists(future) && !File.Exists(futurePartial) && wr.Problems == 3, $"{wr}");

        // the path may not be swapped under the check (a download finishing, a sync client)
        var swapDir = Path.Combine(tempRoot, "swap-files"); Directory.CreateDirectory(swapDir);
        var swapPath = Path.Combine(swapDir, "swap.txt"); File.WriteAllBytes(swapPath, hGenuine);
        var before = new FileInfo(swapPath).LastWriteTimeUtc;
        Checker.AfterHashHook = path =>
        {
            Checker.AfterHashHook = null;
            File.WriteAllBytes(path + ".other", hGenuine);                 // same size, same bytes: only the date can tell
            File.SetLastWriteTimeUtc(path + ".other", before.AddMinutes(7));
            File.Move(path + ".other", path, true);
        };
        CheckResult swapped;
        try { swapped = Checker.Check(swapPath, TrustPolicy.FromFolder(hHome.Trust, now), now); }
        finally { Checker.AfterHashHook = null; }
        Expect("113d a file replaced by another under the check is not called verified", swapped.Status == "CHANGED" && swapped.Reason.Contains("while it was being checked"), $"{swapped.Status}: {swapped.Reason}");

        // approving again after the share failed puts the certificate there instead of refusing for ever
        var aHome = NewCompany("approve-again"); var aShare = Path.Combine(tempRoot, "approve-again-share");
        Authority.ShareSetup(aHome, aShare);
        var aDept = new Home(Path.Combine(tempRoot, "approve-again-dept"));
        Department.Request(aDept, "Finance Department", true, now);
        Department.PublishRequest(aDept, "Finance Department", aShare);
        var aKey = Department.RequestKeyFingerprint(aDept, "Finance Department");
        var certFolder = Path.Combine(aShare, "Certificates");
        Directory.Delete(certFolder); File.WriteAllText(certFolder, "a file where the folder should be");
        var firstTry = Throws<SealException>(() => Authority.Approve(aHome, "Finance Department", aKey, 365, now), "could not be put in the company share");
        File.Delete(certFolder);
        var secondTry = Authority.Approve(aHome, "Finance Department", aKey, 365, now);
        Expect("113e a share that failed during approve does not burn the department's key: approving again puts the certificate there", firstTry && secondTry.Contains("Approved") && File.Exists(Path.Combine(certFolder, "finance-department.pem"))
            && Authority.List(aHome, now).Count(l => l.Contains("Finance Department")) == 1);
        Department.PublishRequest(aDept, "Finance Department", aShare); // asked again, this time with the wrong key
        Expect("113f the path that puts an issued certificate in the share again still checks the key", Throws<SealException>(() => Authority.Approve(aHome, "Finance Department", "AAAA BBBB CCCC DDDD", 365, now), "do not approve"));

        // look alike names
        Expect("113g a variation selector does not make a look alike name", Throws<SealException>(() => Names.CleanStrict("Marketing\uFE0F Department", "name")) && Throws<SealException>(() => Names.CleanStrict("Fina\uFE0Fnce", "name")));
        // stray words are not swallowed
        Expect("113h a stray word on a command that takes no file names is refused", Cli("authority", "list", "oops", "--home", hHome.Root).Code == 2 && Cli("uninstall", "everything").Code == 2);
        // a damaged list of withdrawn certificates is named, not "something unexpected"
        var damagedHome = NewCompany("damaged-list");
        File.WriteAllText(damagedHome.RevokedList, "{\"revoked\":[{\"serial\":\"not hex\",\"name\":\"x\",\"revoked_at\":\"2026-01-01T00:00:00Z\",\"reason\":\"x\"}]}");
        var damagedRun = Cli("authority", "list", "--home", damagedHome.Root);
        Expect("113i a damaged list of withdrawn certificates is explained", damagedRun.Code == 2 && damagedRun.Err.Contains("cannot be read"), damagedRun.Err);
    }

    // ----- names that look like other names
    Expect("112 a name with a letter that draws nothing is refused", Throws<SealException>(() => Names.CleanStrict("MarketingㅤDepartment", "name")) && Throws<SealException>(() => Names.CleanStrict("Fina⠀nce", "name")));
    Expect("112b a mark with no letter under it, and a pile of marks, are refused", Throws<SealException>(() => Names.CleanStrict("́Marketing", "name")) && Throws<SealException>(() => Names.CleanStrict("Mar ́keting", "name"))
        && Throws<SealException>(() => Names.CleanStrict("Má̂̃̄rketing", "name")));
    Expect("112c ordinary accents still work", Names.CleanStrict("Département Café", "name") == "Département Café" && Names.CleanStrict("Café", "name") == "Café");
}

// ---------------------------------------------------------------------- dates people read are in the computer's own time zone
{
    TimeZoneInfo? toronto = null;
    foreach (var id in new[] { "America/Toronto", "Eastern Standard Time" })
    {
        try { toronto = TimeZoneInfo.FindSystemTimeZoneById(id); break; } catch (Exception e) when (e is TimeZoneNotFoundException or InvalidTimeZoneException) { }
    }

    if (toronto == null) Expect("109 this computer has no Toronto time zone, so the date checks were skipped", true);
    else
    {
        var normal = Time.ReadingZone;
        Time.ReadingZone = toronto; // the checks below pin one zone so the answers do not depend on where the tests run
        try
        {
            string D(string utc) => Time.Day(Time.ParseIso(utc));
            string T(string utc) => Time.Full(Time.ParseIso(utc));
            // A note written at 8:05 PM on Oct 26 must not say Oct 27, which is what UTC would show.
            Expect("109 8:05 PM on Oct 26 in Toronto is Oct 26, not the UTC date Oct 27", D("2026-10-27T00:05:00Z") == "Oct 26, 2026", D("2026-10-27T00:05:00Z"));
            Expect("109b midday stays on the same day", D("2026-10-26T16:00:00Z") == "Oct 26, 2026", D("2026-10-26T16:00:00Z"));
            Expect("109c summer time: 11:30 PM on Jun 30 is Jun 30", D("2026-07-01T03:30:00Z") == "Jun 30, 2026", D("2026-07-01T03:30:00Z"));
            Expect("109d winter time: 11:30 PM on Dec 31 is Dec 31, not New Year's Day", D("2027-01-01T04:30:00Z") == "Dec 31, 2026", D("2027-01-01T04:30:00Z"));
            Expect("109e the night the clocks go back (Nov 1) stays Nov 1 on both sides", D("2026-11-01T04:30:00Z") == "Nov 01, 2026" && D("2026-11-01T06:30:00Z") == "Nov 01, 2026", D("2026-11-01T04:30:00Z") + " / " + D("2026-11-01T06:30:00Z"));
            Expect("109f the time of day reads in the computer's zone with the label", T("2026-10-27T00:05:00Z") == "Oct 26, 2026 8:05 PM local time", T("2026-10-27T00:05:00Z"));
            Expect("109g noon and midnight read as 12 PM and 12 AM", T("2026-01-15T17:00:00Z") == "Jan 15, 2026 12:00 PM local time" && T("2026-01-15T05:00:00Z") == "Jan 15, 2026 12:00 AM local time", T("2026-01-15T17:00:00Z") + " / " + T("2026-01-15T05:00:00Z"));
            Expect("109h the stamps kept inside files stay UTC with a Z", Time.Iso(Time.ParseIso("2026-10-27T00:05:00Z")) == "2026-10-27T00:05:00Z");

            // The whole way through: IT withdraws a department at 9:30 PM on Oct 19 (01:30 UTC on Oct 20); the note a person reads must say Oct 19.
            var tzHome = NewCompany("tz-dates");
            var tzDept = MakeDepartment(tzHome, "Marketing Department");
            var tzFile = Seal(doc, tzDept);
            Authority.Revoke(tzHome, "Marketing Department", null, "laptop lost", 4000, Time.ParseIso("2026-10-20T01:30:00Z"));
            var tzResult = Full(tzFile, tzHome.Trust);
            Expect("109i the withdrawn note reads Oct 19, the date where the reader is, not Oct 20", tzResult.Status == "REVOKED" && tzResult.Reason.Contains("on Oct 19, 2026 (laptop lost)") && !tzResult.Reason.Contains("Oct 20"), $"{tzResult.Status}: {tzResult.Reason}");
            Time.ReadingZone = TimeZoneInfo.Utc;
            Expect("109j a computer set to UTC says UTC", T("2026-10-27T00:05:00Z") == "Oct 27, 2026 12:05 AM UTC", T("2026-10-27T00:05:00Z"));
        }
        finally { Time.ReadingZone = normal; }
    }
}

// ---------------------------------------------------------------------------------- done
try { Directory.Delete(tempRoot, true); } catch (IOException) { }
var failed = results.Where(r => !r.Ok).ToList();
Console.WriteLine($"\n{results.Count - failed.Count} of {results.Count} checks passed in {started.Elapsed.TotalSeconds:F1}s.");
return failed.Count == 0 ? 0 : 1;
