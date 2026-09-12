package acknowledgement

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
)

const decisionClockSkew = 5 * time.Second

type Config struct {
	Repository Repository
	Plans      PlanReader
	Authorizer Authorizer
	Clock      func() time.Time
}

type Service struct{ config Config }

func NewService(config Config) (*Service, error) {
	if config.Repository == nil || config.Plans == nil || config.Authorizer == nil {
		return nil, acknowledgementError(generated.ErrorCodeInputInvalid, "acknowledgement-config")
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	return &Service{config: config}, nil
}

func (service *Service) Submit(ctx context.Context, candidate Candidate) error {
	_, err := service.Decide(ctx, candidate)
	return err
}

func (service *Service) Reject(ctx context.Context, rejection AdapterRejection) error {
	validReason := rejection.ReasonCode == generated.ErrorCodeInputInvalid || rejection.ReasonCode == generated.ErrorCodeAuthorizationDenied
	if service == nil || ctx == nil || !identity.ValidPrincipal(rejection.Human) || identity.EffectivePrincipalKind(rejection.Human) != identity.PrincipalHuman || !authorization.ValidIdentifier(rejection.AuthorityID) || !validDigest(rejection.AttemptDigest) || !validReason || rejection.RejectedAt.IsZero() || rejection.RejectedAt.Location() != time.UTC {
		return acknowledgementError(generated.ErrorCodeInputInvalid, "acknowledgement-adapter-rejection")
	}
	attribution, err := audit.NewAttribution(rejection.Human, &rejection.Human, nil)
	if err != nil {
		return acknowledgementError(generated.ErrorCodeIntegrityFailure, "acknowledgement-denial-audit")
	}
	correlationID := "denial-" + strings.TrimPrefix(rejection.AttemptDigest, "sha256:")[:32]
	return service.config.Repository.RecordDenial(ctx, DenialRecord{TargetKind: "acknowledgement-authority", TargetID: rejection.AuthorityID, CorrelationID: correlationID, AttemptDigest: rejection.AttemptDigest, ReasonCode: rejection.ReasonCode, RejectedAt: rejection.RejectedAt, Attribution: attribution})
}

func (service *Service) Request(ctx context.Context, scope Scope, planID string) (RequestCard, error) {
	if service == nil || ctx == nil || !validScope(scope) || !authorization.ValidIdentifier(planID) {
		return RequestCard{}, acknowledgementError(generated.ErrorCodeInputInvalid, "acknowledgement-request")
	}
	plan, err := service.config.Plans.Get(ctx, planID)
	if err != nil {
		return RequestCard{}, err
	}
	if err := service.validCurrentHumanPlan(ctx, scope.Human, plan); err != nil {
		return RequestCard{}, err
	}
	now := service.config.Clock().UTC().Truncate(time.Second)
	expiresAt := mustTime(plan.ExpiresAt)
	if expiresAt.IsZero() || !now.Before(expiresAt) {
		return RequestCard{}, acknowledgementError(generated.ErrorCodePlanStale, "plan")
	}
	nonceDigest := digest(scope.Nonce)
	request := generated.AcknowledgementRequest{
		Schema: generated.SchemaIDAcknowledgementRequest, SchemaVersion: "1.0.0",
		PlanID: plan.PlanID, PlanDigest: plan.PlanDigest, TargetDigest: plan.Binding.TargetDigest,
		ReasonDigest: plan.Binding.ReasonDigest, HumanID: scope.Human.ID, AuthorityID: scope.AuthorityID,
		NonceDigest: nonceDigest, StateRevision: plan.Binding.StateRevision,
		RecoveryEpoch: plan.Binding.RecoveryEpoch, ExpiresAt: plan.ExpiresAt,
		Extensions: []generated.ContractExtension{},
	}
	if !validContract(generated.SchemaIDAcknowledgementRequest, request) {
		return RequestCard{}, acknowledgementError(generated.ErrorCodeInputInvalid, "acknowledgement-request")
	}
	acknowledgementID := "ack-" + strings.TrimPrefix(digest("acknowledgement-v1\x00"+plan.PlanID+"\x00"+nonceDigest), "sha256:")[:32]
	pending := outcomeFrom(request, acknowledgementID, "pending", now, proofDigest(request, "pending", now))
	attribution, err := audit.NewAttribution(scope.Human, &scope.Human, nil)
	if err != nil {
		return RequestCard{}, acknowledgementError(generated.ErrorCodeInputInvalid, "acknowledgement-attribution")
	}
	stored, created, err := service.config.Repository.Create(ctx, CreateRecord{Request: request, Pending: pending, CreatedAt: now, Attribution: attribution})
	if err != nil {
		return RequestCard{}, err
	}
	if !created {
		if stored.Acknowledgement.Status != "pending" || !sameRequest(stored.Request, request) {
			return RequestCard{}, acknowledgementError(generated.ErrorCodePlanStale, "acknowledgement-request")
		}
		acknowledgementID = stored.Acknowledgement.AcknowledgementID
	}
	return RequestCard{Request: request, AcknowledgementID: acknowledgementID, Nonce: scope.Nonce}, nil
}

func (service *Service) Decide(ctx context.Context, candidate Candidate) (generated.Acknowledgement, error) {
	if service == nil || ctx == nil || !validCandidate(candidate) {
		return generated.Acknowledgement{}, acknowledgementError(generated.ErrorCodeAuthorizationDenied, "acknowledgement-candidate")
	}
	stored, err := service.config.Repository.Get(ctx, candidate.PlanID)
	if err != nil {
		return generated.Acknowledgement{}, err
	}
	if !candidateMatchesRequest(candidate, stored.Request) {
		return generated.Acknowledgement{}, service.denyCandidate(ctx, stored, candidate, candidateMismatch(candidate, stored.Request))
	}
	if stored.Acknowledgement.Status != "pending" {
		if stored.Acknowledgement.Status == candidate.Action {
			return stored.Acknowledgement, nil
		}
		return generated.Acknowledgement{}, service.denyCandidate(ctx, stored, candidate, acknowledgementError(generated.ErrorCodePlanStale, "acknowledgement"))
	}
	now := service.config.Clock().UTC().Truncate(time.Second)
	if !now.Before(mustTime(stored.Request.ExpiresAt)) {
		if _, err := service.expire(ctx, stored, now); err != nil {
			return generated.Acknowledgement{}, err
		}
		return generated.Acknowledgement{}, service.denyCandidate(ctx, stored, candidate, acknowledgementError(generated.ErrorCodePlanStale, "acknowledgement"))
	}
	if candidate.DecidedAt.Before(now.Add(-decisionClockSkew)) || candidate.DecidedAt.After(now.Add(decisionClockSkew)) {
		return generated.Acknowledgement{}, service.denyCandidate(ctx, stored, candidate, acknowledgementError(generated.ErrorCodePlanStale, "acknowledgement"))
	}
	plan, err := service.config.Plans.Get(ctx, candidate.PlanID)
	if err != nil {
		return generated.Acknowledgement{}, err
	}
	if err := service.validCurrentHumanPlan(ctx, candidate.Human, plan); err != nil {
		return generated.Acknowledgement{}, service.denyCandidate(ctx, stored, candidate, err)
	}
	outcome := outcomeFrom(stored.Request, stored.Acknowledgement.AcknowledgementID, candidate.Action, now, proofDigest(stored.Request, candidate.Action, now))
	attribution, err := audit.NewAttribution(candidate.Human, &candidate.Human, nil)
	if err != nil {
		return generated.Acknowledgement{}, acknowledgementError(generated.ErrorCodeAuthorizationDenied, "acknowledgement-attribution")
	}
	decided, changed, err := service.config.Repository.Decide(ctx, DecisionRecord{Expected: stored.Request, Outcome: outcome, DecidedAt: now, Attribution: attribution})
	if err != nil {
		return generated.Acknowledgement{}, err
	}
	if !changed && decided.Acknowledgement.ProofDigest != outcome.ProofDigest {
		return generated.Acknowledgement{}, acknowledgementError(generated.ErrorCodePlanStale, "acknowledgement")
	}
	return decided.Acknowledgement, nil
}

// Status returns the durable provider-neutral state and terminalizes a pending
// request whose exact plan expiry has elapsed. Expiry never grants authority.
func (service *Service) Status(ctx context.Context, planID string) (generated.Acknowledgement, error) {
	if service == nil || ctx == nil || !authorization.ValidIdentifier(planID) {
		return generated.Acknowledgement{}, acknowledgementError(generated.ErrorCodeInputInvalid, "acknowledgement")
	}
	stored, err := service.config.Repository.Get(ctx, planID)
	if err != nil {
		return generated.Acknowledgement{}, err
	}
	now := service.config.Clock().UTC().Truncate(time.Second)
	if stored.Acknowledgement.Status == "pending" && !now.Before(mustTime(stored.Request.ExpiresAt)) {
		stored, err = service.expire(ctx, stored, now)
		if err != nil {
			return generated.Acknowledgement{}, err
		}
	}
	return stored.Acknowledgement, nil
}

func (service *Service) expire(ctx context.Context, stored Stored, now time.Time) (Stored, error) {
	outcome := outcomeFrom(stored.Request, stored.Acknowledgement.AcknowledgementID, "expired", now, proofDigest(stored.Request, "expired", now))
	attribution := audit.Attribution{AuthenticatedPrincipalID: ExpiryPrincipalID, AuthenticatedPrincipalMethod: ExpiryPrincipalMode}
	expired, changed, err := service.config.Repository.Decide(ctx, DecisionRecord{Expected: stored.Request, Outcome: outcome, DecidedAt: now, Attribution: attribution})
	if err != nil {
		return Stored{}, err
	}
	if !changed && expired.Acknowledgement.Status != "expired" {
		return Stored{}, acknowledgementError(generated.ErrorCodePlanStale, "acknowledgement")
	}
	return expired, nil
}

func (service *Service) VerifyForExecution(ctx context.Context, planID string) (generated.Acknowledgement, error) {
	if service == nil || ctx == nil || !authorization.ValidIdentifier(planID) {
		return generated.Acknowledgement{}, acknowledgementError(generated.ErrorCodeInputInvalid, "acknowledgement-proof")
	}
	stored, err := service.config.Repository.Get(ctx, planID)
	if err != nil {
		return generated.Acknowledgement{}, err
	}
	if stored.Acknowledgement.Status != "approved" || stored.Consumed {
		cause := acknowledgementError(generated.ErrorCodePlanStale, "acknowledgement-proof")
		return generated.Acknowledgement{}, service.denyStored(ctx, stored, "execution-replay", cause)
	}
	plan, err := service.config.Plans.Get(ctx, planID)
	if err != nil {
		return generated.Acknowledgement{}, err
	}
	if !proofMatchesPlan(stored, plan) {
		cause := acknowledgementError(generated.ErrorCodeAuthorizationDenied, "acknowledgement-proof")
		return generated.Acknowledgement{}, service.denyStored(ctx, stored, "execution-binding", cause)
	}
	human := identity.Principal{ID: stored.Request.HumanID, Method: identity.SlackSocketModeMethod, Kind: identity.PrincipalHuman}
	if err := service.validCurrentHumanPlan(ctx, human, plan); err != nil {
		return generated.Acknowledgement{}, service.denyStored(ctx, stored, "execution-authorization", err)
	}
	now := service.config.Clock().UTC().Truncate(time.Second)
	if !now.Before(mustTime(stored.Acknowledgement.ExpiresAt)) {
		cause := acknowledgementError(generated.ErrorCodePlanStale, "acknowledgement-proof")
		return generated.Acknowledgement{}, service.denyStored(ctx, stored, "execution-expired", cause)
	}
	if err := service.config.Plans.ValidateCurrent(ctx, plan); err != nil {
		cause := acknowledgementError(generated.ErrorCodePlanStale, "plan")
		return generated.Acknowledgement{}, service.denyStored(ctx, stored, "execution-stale", cause)
	}
	consumed, changed, err := service.config.Repository.Consume(ctx, planID, now)
	if err != nil {
		return generated.Acknowledgement{}, err
	}
	if !changed || !consumed.Consumed {
		return generated.Acknowledgement{}, acknowledgementError(generated.ErrorCodePlanStale, "acknowledgement-proof")
	}
	return consumed.Acknowledgement, nil
}

func (service *Service) denyCandidate(ctx context.Context, stored Stored, candidate Candidate, cause error) error {
	code := errorCode(cause)
	if code == "" {
		code = generated.ErrorCodeAuthorizationDenied
	}
	attribution, err := audit.NewAttribution(candidate.Human, &candidate.Human, nil)
	if err != nil {
		return acknowledgementError(generated.ErrorCodeIntegrityFailure, "acknowledgement-denial-audit")
	}
	attempt := strings.Join([]string{"candidate-denial-v1", candidate.Action, candidate.PlanID, candidate.PlanDigest, candidate.TargetDigest, candidate.ReasonDigest, digest(candidate.Nonce), intString(candidate.StateRevision), intString(candidate.RecoveryEpoch), candidate.ExpiresAt.UTC().Format(time.RFC3339)}, "\x00")
	record := DenialRecord{TargetKind: "plan", TargetID: stored.Request.PlanID, CorrelationID: stored.Acknowledgement.AcknowledgementID, AttemptDigest: digest(attempt), ReasonCode: code, RejectedAt: service.config.Clock().UTC().Truncate(time.Second), Attribution: attribution}
	if err := service.config.Repository.RecordDenial(ctx, record); err != nil {
		return acknowledgementError(generated.ErrorCodeIntegrityFailure, "acknowledgement-denial-audit")
	}
	return cause
}

func (service *Service) denyStored(ctx context.Context, stored Stored, kind string, cause error) error {
	code := errorCode(cause)
	attribution := audit.Attribution{AuthenticatedPrincipalID: stored.Request.HumanID, AuthenticatedPrincipalMethod: identity.SlackSocketModeMethod}
	record := DenialRecord{TargetKind: "plan", TargetID: stored.Request.PlanID, CorrelationID: stored.Acknowledgement.AcknowledgementID, AttemptDigest: digest(strings.Join([]string{"proof-denial-v1", kind, stored.Acknowledgement.ProofDigest, code}, "\x00")), ReasonCode: code, RejectedAt: service.config.Clock().UTC().Truncate(time.Second), Attribution: attribution}
	if err := service.config.Repository.RecordDenial(ctx, record); err != nil {
		return acknowledgementError(generated.ErrorCodeIntegrityFailure, "acknowledgement-denial-audit")
	}
	return cause
}

func (service *Service) validCurrentHumanPlan(ctx context.Context, human identity.Principal, plan generated.Plan) error {
	if !identity.ValidPrincipal(human) || identity.EffectivePrincipalKind(human) != identity.PrincipalHuman || plan.AuthorizationBranch != string(authorization.BranchHuman) {
		return acknowledgementError(generated.ErrorCodeAuthorizationDenied, "acknowledgement-human")
	}
	if err := service.config.Plans.ValidateCurrent(ctx, plan); err != nil {
		return acknowledgementError(generated.ErrorCodePlanStale, "plan")
	}
	targets := uniqueTargets(plan)
	if len(targets) == 0 {
		return acknowledgementError(generated.ErrorCodeAuthorizationDenied, "acknowledgement-target")
	}
	for _, targetID := range targets {
		target := authorization.Target{Capability: "plan.acknowledge", ResourceKind: "plan-target", ResourceID: targetID}
		decision, err := service.config.Authorizer.Authorize(ctx, human, authorization.Request{Action: authorization.ActionAcknowledge, Target: target, Plan: &plan, Branches: []authorization.Branch{authorization.BranchHuman}})
		if err != nil {
			return acknowledgementError(generated.ErrorCodeDependencyUnavailable, "authorization-policy")
		}
		if !decision.Allowed || decision.PrincipalID != human.ID || decision.Action != authorization.ActionAcknowledge || decision.Target != target || decision.Branch == nil || *decision.Branch != authorization.BranchHuman || decision.PlanDigest != plan.PlanDigest || decision.StateRevision != plan.Binding.StateRevision || decision.RecoveryEpoch != plan.Binding.RecoveryEpoch {
			return acknowledgementError(generated.ErrorCodeAuthorizationDenied, "acknowledgement-human")
		}
	}
	return nil
}

func uniqueTargets(plan generated.Plan) []string {
	seen := map[string]bool{}
	for _, operation := range plan.Operations {
		seen[operation.TargetID] = true
	}
	result := make([]string, 0, len(seen))
	for target := range seen {
		result = append(result, target)
	}
	sort.Strings(result)
	return result
}

func candidateMatchesRequest(candidate Candidate, request generated.AcknowledgementRequest) bool {
	return candidate.Human.ID == request.HumanID && candidate.AuthorityID == request.AuthorityID && candidate.PlanID == request.PlanID && candidate.PlanDigest == request.PlanDigest && candidate.TargetDigest == request.TargetDigest && candidate.ReasonDigest == request.ReasonDigest && secureEqual(digest(candidate.Nonce), request.NonceDigest) && candidate.StateRevision == request.StateRevision && candidate.RecoveryEpoch == request.RecoveryEpoch && candidate.ExpiresAt.UTC().Truncate(time.Second).Format(time.RFC3339) == request.ExpiresAt
}

func candidateMismatch(candidate Candidate, request generated.AcknowledgementRequest) error {
	if candidate.RecoveryEpoch != request.RecoveryEpoch {
		return acknowledgementError(generated.ErrorCodeRecoveryEpochMismatch, "acknowledgement")
	}
	if candidate.StateRevision != request.StateRevision {
		return acknowledgementError(generated.ErrorCodePlanStale, "acknowledgement")
	}
	return acknowledgementError(generated.ErrorCodeAuthorizationDenied, "acknowledgement")
}

func proofMatchesPlan(stored Stored, plan generated.Plan) bool {
	request := stored.Request
	proof := stored.Acknowledgement
	return request.PlanID == plan.PlanID && request.PlanDigest == plan.PlanDigest && request.TargetDigest == plan.Binding.TargetDigest && request.ReasonDigest == plan.Binding.ReasonDigest && request.StateRevision == plan.Binding.StateRevision && request.RecoveryEpoch == plan.Binding.RecoveryEpoch && proof.PlanID == request.PlanID && proof.PlanDigest == request.PlanDigest && proof.TargetDigest == request.TargetDigest && proof.ReasonDigest == request.ReasonDigest && proof.HumanID == request.HumanID && proof.AuthorityID == request.AuthorityID && proof.NonceDigest == request.NonceDigest && proof.StateRevision == request.StateRevision && proof.RecoveryEpoch == request.RecoveryEpoch && proof.ExpiresAt == request.ExpiresAt && proof.ProofDigest == proofDigest(request, proof.Status, mustTime(proof.ReceivedAt))
}

func outcomeFrom(request generated.AcknowledgementRequest, acknowledgementID, status string, receivedAt time.Time, proof string) generated.Acknowledgement {
	return generated.Acknowledgement{Schema: generated.SchemaIDAcknowledgement, SchemaVersion: "1.0.0", PlanID: request.PlanID, PlanDigest: request.PlanDigest, TargetDigest: request.TargetDigest, ReasonDigest: request.ReasonDigest, HumanID: request.HumanID, AuthorityID: request.AuthorityID, NonceDigest: request.NonceDigest, StateRevision: request.StateRevision, RecoveryEpoch: request.RecoveryEpoch, ExpiresAt: request.ExpiresAt, AcknowledgementID: acknowledgementID, ProofDigest: proof, Status: status, ReceivedAt: receivedAt.UTC().Truncate(time.Second).Format(time.RFC3339), Extensions: []generated.ContractExtension{}}
}

func proofDigest(request generated.AcknowledgementRequest, status string, at time.Time) string {
	return digest(strings.Join([]string{"acknowledgement-proof-v1", request.PlanID, request.PlanDigest, request.TargetDigest, request.ReasonDigest, request.HumanID, request.AuthorityID, request.NonceDigest, request.ExpiresAt, status, at.UTC().Truncate(time.Second).Format(time.RFC3339), intString(request.StateRevision), intString(request.RecoveryEpoch)}, "\x00"))
}

func validScope(scope Scope) bool {
	return identity.ValidPrincipal(scope.Human) && identity.EffectivePrincipalKind(scope.Human) == identity.PrincipalHuman && authorization.ValidIdentifier(scope.AuthorityID) && validNonce(scope.Nonce)
}

func validCandidate(candidate Candidate) bool {
	return (candidate.Action == ActionApprove || candidate.Action == ActionReject) && validScope(Scope{Human: candidate.Human, AuthorityID: candidate.AuthorityID, Nonce: candidate.Nonce}) && authorization.ValidIdentifier(candidate.PlanID) && validDigest(candidate.PlanDigest) && validDigest(candidate.TargetDigest) && validDigest(candidate.ReasonDigest) && candidate.StateRevision >= 0 && candidate.RecoveryEpoch >= 0 && !candidate.ExpiresAt.IsZero() && !candidate.DecidedAt.IsZero()
}

func validNonce(value string) bool {
	if value == "" || len(value) > 512 || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func sameRequest(left, right generated.AcknowledgementRequest) bool {
	leftJSON, _ := json.Marshal(left)
	rightJSON, _ := json.Marshal(right)
	return secureEqual(string(leftJSON), string(rightJSON))
}

func validContract(schema string, value any) bool {
	raw, err := json.Marshal(value)
	return err == nil && generated.ValidateContractJSON(schema, raw, generated.ContractExact) == nil
}

func validDigest(value string) bool {
	if len(value) != 71 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil && len(decoded) == sha256.Size
}

func secureEqual(left, right string) bool {
	return len(left) == len(right) && subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}

func digest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func intString(value int64) string {
	const digits = "0123456789"
	if value == 0 {
		return "0"
	}
	var buffer [20]byte
	position := len(buffer)
	for value > 0 {
		position--
		buffer[position] = digits[value%10]
		value /= 10
	}
	return string(buffer[position:])
}

func mustTime(value string) time.Time { parsed, _ := time.Parse(time.RFC3339, value); return parsed }

func acknowledgementError(code, target string) error { return failure.New(code, target, false) }

func errorCode(err error) string {
	if stable, ok := failure.As(err); ok {
		return stable.Code
	}
	return ""
}
