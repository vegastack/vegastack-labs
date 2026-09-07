package release

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"testing"
	"time"

	ct "github.com/google/certificate-transparency-go"
	cttls "github.com/google/certificate-transparency-go/tls"
	ctx509 "github.com/google/certificate-transparency-go/x509"
	ctx509util "github.com/google/certificate-transparency-go/x509util"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	protodsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	protorekor "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	testca "github.com/sigstore/sigstore-go/pkg/testing/ca"
	"github.com/sigstore/sigstore-go/pkg/tlog"
	"github.com/sigstore/sigstore/pkg/signature"
	sigdsse "github.com/sigstore/sigstore/pkg/signature/dsse"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

const (
	syntheticIdentity = "https://example.invalid/vegastack/synthetic-release"
	syntheticIssuer   = "https://issuer.example.invalid"
)

func TestSigstoreBundleVerifierAcceptsFullySyntheticV03Bundle(t *testing.T) {
	fixture := newSyntheticFixture(t, syntheticFixtureOptions{})
	if err := (SigstoreBundleVerifier{}).Verify(
		context.Background(), bytes.NewReader(fixture.artifact), fixture.bundleJSON, fixture.policy,
	); err != nil {
		t.Fatal(err)
	}
}

func TestSigstoreBundleVerifierRejectsInvalidEvidence(t *testing.T) {
	fixture := newSyntheticFixture(t, syntheticFixtureOptions{})
	second := newSyntheticFixture(t, syntheticFixtureOptions{})
	wrongSignature := cloneBundle(t, fixture.bundle)
	wrongSignature.GetDsseEnvelope().Signatures[0].Sig[0] ^= 1
	unsigned := cloneBundle(t, fixture.bundle)
	unsigned.GetDsseEnvelope().Signatures = nil
	missingTimestamp := cloneBundle(t, fixture.bundle)
	missingTimestamp.VerificationMaterial.TimestampVerificationData = nil
	missingTimestamp.VerificationMaterial.TlogEntries[0].InclusionPromise = nil
	missingProof := cloneBundle(t, fixture.bundle)
	missingProof.VerificationMaterial.TlogEntries[0].InclusionProof = nil
	unsupportedVersion := cloneBundle(t, fixture.bundle)
	unsupportedVersion.MediaType = "application/vnd.dev.sigstore.bundle.v0.4+json"
	noSCT := newSyntheticFixture(t, syntheticFixtureOptions{withoutSCT: true})
	expired := newSyntheticFixture(t, syntheticFixtureOptions{expiredAtObserver: true})

	tests := []struct {
		name     string
		artifact []byte
		bundle   []byte
		policy   generated.ReleaseTrustPolicy
	}{
		{name: "tampered-content", artifact: []byte("tampered"), bundle: fixture.bundleJSON, policy: fixture.policy},
		{name: "wrong-signature", artifact: fixture.artifact, bundle: marshalBundle(t, wrongSignature), policy: fixture.policy},
		{name: "unsigned-content", artifact: fixture.artifact, bundle: marshalBundle(t, unsigned), policy: fixture.policy},
		{name: "wrong-identity", artifact: fixture.artifact, bundle: fixture.bundleJSON, policy: policyWith(fixture.policy, "wrong", syntheticIssuer)},
		{name: "wrong-issuer", artifact: fixture.artifact, bundle: fixture.bundleJSON, policy: policyWith(fixture.policy, syntheticIdentity, "wrong")},
		{name: "untrusted-root", artifact: fixture.artifact, bundle: fixture.bundleJSON, policy: second.policy},
		{name: "missing-sct", artifact: noSCT.artifact, bundle: noSCT.bundleJSON, policy: noSCT.policy},
		{name: "missing-observer-timestamp", artifact: fixture.artifact, bundle: marshalBundle(t, missingTimestamp), policy: fixture.policy},
		{name: "missing-transparency-proof", artifact: fixture.artifact, bundle: marshalBundle(t, missingProof), policy: fixture.policy},
		{name: "expired-at-observer-time", artifact: expired.artifact, bundle: expired.bundleJSON, policy: expired.policy},
		{name: "malformed", artifact: fixture.artifact, bundle: []byte(`{"mediaType":`), policy: fixture.policy},
		{name: "unsupported-media", artifact: fixture.artifact, bundle: marshalBundle(t, unsupportedVersion), policy: fixture.policy},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := ioVerify(t, test.artifact, test.bundle, test.policy)
			releaseErr := assertReleaseError(t, err, generated.ErrorCodeEvidenceInvalid)
			if releaseErr.Target != targetBundleSignature {
				t.Fatalf("target = %q, want %q", releaseErr.Target, targetBundleSignature)
			}
		})
	}
}

func TestSigstoreBundleVerifierBoundsBundleAndHonorsCancellation(t *testing.T) {
	fixture := newSyntheticFixture(t, syntheticFixtureOptions{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := ioVerifyWithContext(t, ctx, fixture.artifact, fixture.bundleJSON, fixture.policy)
	assertReleaseError(t, err, generated.ErrorCodeInterrupted)

	oversized := make([]byte, maxBundleBytes+1)
	_, err = ioVerify(t, fixture.artifact, oversized, fixture.policy)
	assertReleaseError(t, err, generated.ErrorCodeInputInvalid)

	oversizedPolicy := fixture.policy
	oversizedPolicy.TrustedRoot = make([]byte, maxPolicyBytes+1)
	_, err = ioVerify(t, fixture.artifact, fixture.bundleJSON, oversizedPolicy)
	assertReleaseError(t, err, generated.ErrorCodeInputInvalid)
}

func ioVerify(t *testing.T, artifact, bundleJSON []byte, policy generated.ReleaseTrustPolicy) (bool, error) {
	t.Helper()
	return ioVerifyWithContext(t, context.Background(), artifact, bundleJSON, policy)
}

func ioVerifyWithContext(t *testing.T, ctx context.Context, artifact, bundleJSON []byte, policy generated.ReleaseTrustPolicy) (bool, error) {
	t.Helper()
	err := (SigstoreBundleVerifier{}).Verify(ctx, bytes.NewReader(artifact), bundleJSON, policy)
	return err == nil, err
}

type syntheticFixtureOptions struct {
	withoutSCT        bool
	expiredAtObserver bool
	artifact          []byte
}

type syntheticFixture struct {
	artifact   []byte
	bundle     *protobundle.Bundle
	bundleJSON []byte
	policy     generated.ReleaseTrustPolicy
}

func newSyntheticFixture(t *testing.T, options syntheticFixtureOptions) syntheticFixture {
	t.Helper()
	artifact := options.artifact
	if artifact == nil {
		artifact = []byte("synthetic VegaStack release artifact\n")
	}
	identity, issuer := syntheticIdentity, syntheticIssuer
	now := time.Now().UTC().Truncate(time.Second)
	leafNotBefore, leafNotAfter, sctAt := now.Add(-time.Minute), now.Add(10*time.Minute), now
	if options.expiredAtObserver {
		leafNotBefore, leafNotAfter, sctAt = now.Add(-10*time.Minute), now.Add(-5*time.Minute), now.Add(-7*time.Minute)
	}
	integratedTime := now.Add(time.Minute)

	virtual, err := testca.NewVirtualSigstore()
	if err != nil {
		t.Fatal(err)
	}
	fulcioRoot, fulcioRootKey, err := testca.GenerateRootCa()
	if err != nil {
		t.Fatal(err)
	}
	fulcioIntermediate, fulcioIntermediateKey, err := testca.GenerateFulcioIntermediate(fulcioRoot, fulcioRootKey)
	if err != nil {
		t.Fatal(err)
	}
	signingKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ctKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(28), EmailAddresses: []string{identity},
		NotBefore: leafNotBefore, NotAfter: leafNotAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		ExtraExtensions: []pkix.Extension{{
			Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1}, Value: []byte(issuer),
		}},
	}
	preDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, fulcioIntermediate, &signingKey.PublicKey, fulcioIntermediateKey)
	if err != nil {
		t.Fatal(err)
	}
	preCert, err := x509.ParseCertificate(preDER)
	if err != nil {
		t.Fatal(err)
	}
	ctKeyDER, err := x509.MarshalPKIXPublicKey(&ctKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	ctLogID := sha256.Sum256(ctKeyDER)
	if !options.withoutSCT {
		embedSCT(t, leafTemplate, preCert, fulcioIntermediate, fulcioIntermediateKey, signingKey, ctKey, ctLogID, sctAt)
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, fulcioIntermediate, &signingKey.PublicKey, fulcioIntermediateKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}

	artifactDigest := sha256.Sum256(artifact)
	statement := []byte(fmt.Sprintf(
		`{"_type":"https://in-toto.io/Statement/v0.1","predicateType":"https://example.invalid/vegastack/release-fixture/v1","subject":[{"name":"vsk-labs-synthetic-artifact","digest":{"sha256":"%x"}}],"predicate":{}}`,
		artifactDigest,
	))
	signer, err := signature.LoadECDSASignerVerifier(signingKey, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	envelopeSigner, err := dsse.NewEnvelopeSigner(&sigdsse.SignerAdapter{SignatureSigner: signer, Pub: &signingKey.PublicKey})
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := envelopeSigner.SignPayload(context.Background(), "application/vnd.in-toto+json", statement)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := base64.StdEncoding.DecodeString(envelope.Signatures[0].Sig)
	if err != nil {
		t.Fatal(err)
	}
	tlogEntry, err := virtual.GenerateTlogEntry(leaf, envelope, sig, integratedTime.Unix(), true)
	if err != nil {
		t.Fatal(err)
	}
	tlogProto := tlogEntry.TransparencyLogEntry()
	tlogProto.KindVersion = &protorekor.KindVersion{Kind: "dsse", Version: "0.0.1"}
	set, err := virtual.RekorSignPayload(tlog.RekorPayload{
		Body: base64.StdEncoding.EncodeToString(tlogProto.CanonicalizedBody), IntegratedTime: tlogProto.IntegratedTime,
		LogIndex: tlogProto.LogIndex, LogID: hex.EncodeToString(tlogProto.LogId.KeyId),
	})
	if err != nil {
		t.Fatal(err)
	}
	tlogProto.InclusionPromise = &protorekor.InclusionPromise{SignedEntryTimestamp: set}
	timestampResponse, err := virtual.TimestampResponse(sig)
	if err != nil {
		t.Fatal(err)
	}

	pb := &protobundle.Bundle{
		MediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
		VerificationMaterial: &protobundle.VerificationMaterial{
			Content:     &protobundle.VerificationMaterial_Certificate{Certificate: &protocommon.X509Certificate{RawBytes: leaf.Raw}},
			TlogEntries: []*protorekor.TransparencyLogEntry{tlogProto},
			TimestampVerificationData: &protobundle.TimestampVerificationData{
				Rfc3161Timestamps: []*protocommon.RFC3161SignedTimestamp{{SignedTimestamp: timestampResponse}},
			},
		},
		Content: &protobundle.Bundle_DsseEnvelope{DsseEnvelope: &protodsse.Envelope{
			Payload: payload, PayloadType: envelope.PayloadType, Signatures: []*protodsse.Signature{{Sig: sig}},
		}},
	}
	if _, err := bundle.NewBundle(pb); err != nil {
		t.Fatal(err)
	}
	bundleJSON := marshalBundle(t, pb)

	rekorLogs := logsForTrustedRoot(t, virtual.RekorLogs())
	fulcio := &root.FulcioCertificateAuthority{
		Root: fulcioRoot, Intermediates: []*x509.Certificate{fulcioIntermediate},
		ValidityPeriodStart: fulcioRoot.NotBefore, ValidityPeriodEnd: fulcioRoot.NotAfter,
		URI: "https://fulcio.example.invalid",
	}
	ctLogs := map[string]*root.TransparencyLog{
		hex.EncodeToString(ctLogID[:]): {
			BaseURL: "https://ctlog.example.invalid", ID: append([]byte(nil), ctLogID[:]...),
			ValidityPeriodStart: now.Add(-time.Hour), ValidityPeriodEnd: now.Add(time.Hour),
			HashFunc: crypto.SHA256, PublicKey: &ctKey.PublicKey, SignatureHashFunc: crypto.SHA256,
		},
	}
	trustedRoot, err := root.NewTrustedRoot(
		root.TrustedRootMediaType01, []root.CertificateAuthority{fulcio}, ctLogs,
		virtual.TimestampingAuthorities(), rekorLogs,
	)
	if err != nil {
		t.Fatal(err)
	}
	trustedRootJSON, err := json.Marshal(trustedRoot)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := root.NewTrustedRootFromJSON(trustedRootJSON); err != nil {
		t.Fatal(err)
	}
	return syntheticFixture{
		artifact: artifact, bundle: pb, bundleJSON: bundleJSON,
		policy: generated.ReleaseTrustPolicy{
			Schema: generated.SchemaIDReleaseTrustPolicy, SchemaVersion: policySchemaVersion,
			CertificateIdentity: identity, OIDCIssuer: issuer, TrustedRoot: trustedRootJSON,
		},
	}
}

func embedSCT(t *testing.T, template, preCert, issuer *x509.Certificate, issuerKey, signingKey, ctKey *ecdsa.PrivateKey, logID [32]byte, timestamp time.Time) {
	t.Helper()
	sct := ct.SignedCertificateTimestamp{SCTVersion: ct.V1, LogID: ct.LogID{KeyID: logID}, Timestamp: uint64(timestamp.UnixMilli())}
	entry := ct.LogEntry{Leaf: ct.MerkleTreeLeaf{
		Version: ct.V1, LeafType: ct.TimestampedEntryLeafType,
		TimestampedEntry: &ct.TimestampedEntry{
			Timestamp: sct.Timestamp, EntryType: ct.PrecertLogEntryType,
			PrecertEntry: &ct.PreCert{IssuerKeyHash: sha256.Sum256(issuer.RawSubjectPublicKeyInfo), TBSCertificate: preCert.RawTBSCertificate},
		},
	}}
	input, err := ct.SerializeSCTSignatureInput(sct, entry)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(input)
	sig, err := ctKey.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	sct.Signature = ct.DigitallySigned{
		Algorithm: cttls.SignatureAndHashAlgorithm{Hash: cttls.SHA256, Signature: cttls.ECDSA}, Signature: sig,
	}
	list, err := ctx509util.MarshalSCTsIntoSCTList([]*ct.SignedCertificateTimestamp{&sct})
	if err != nil {
		t.Fatal(err)
	}
	tlsList, err := cttls.Marshal(*list)
	if err != nil {
		t.Fatal(err)
	}
	derList, err := asn1.Marshal(tlsList)
	if err != nil {
		t.Fatal(err)
	}
	template.ExtraExtensions = append(template.ExtraExtensions, pkix.Extension{
		Id: asn1.ObjectIdentifier(ctx509.OIDExtensionCTSCT), Value: derList,
	})
	_ = issuerKey
	_ = signingKey
}

func logsForTrustedRoot(t *testing.T, input map[string]*root.TransparencyLog) map[string]*root.TransparencyLog {
	t.Helper()
	output := make(map[string]*root.TransparencyLog, len(input))
	for id, value := range input {
		rawID, err := hex.DecodeString(id)
		if err != nil {
			t.Fatal(err)
		}
		clone := *value
		clone.ID = rawID
		output[id] = &clone
	}
	return output
}

func cloneBundle(t *testing.T, input *protobundle.Bundle) *protobundle.Bundle {
	t.Helper()
	return proto.Clone(input).(*protobundle.Bundle)
}

func marshalBundle(t *testing.T, input *protobundle.Bundle) []byte {
	t.Helper()
	content, err := protojson.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	return content
}

func policyWith(policy generated.ReleaseTrustPolicy, identity, issuer string) generated.ReleaseTrustPolicy {
	policy.CertificateIdentity = identity
	policy.OIDCIssuer = issuer
	return policy
}
