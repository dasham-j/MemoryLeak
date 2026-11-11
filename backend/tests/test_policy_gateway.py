"""Policy gateway tests. Pure logic: no network, no PayPal."""

from __future__ import annotations

from decimal import Decimal

import pytest

from security.policy_gateway import (
    CHECK_APPROVAL,
    CHECK_APPROVED_AMOUNT,
    CHECK_AUTHORIZED_AMOUNT,
    CHECK_PAYEE,
    CHECK_SPENDING_LIMIT,
    PaymentPolicy,
    PaymentProposal,
    UserApproval,
    evaluate,
)

PAYEE = "merchant@acme-saas.example"
ATTACKER = "billing-update@shady-store.example"

POLICY = PaymentPolicy.create(
    authorized_amount=Decimal("20.00"),
    spending_limit=Decimal("50.00"),
    require_approval=True,
    payee_allowlist=[PAYEE],
)
LEGIT = PaymentProposal(amount=Decimal("20.00"), payee=PAYEE)
APPROVAL = UserApproval(approved_amount=Decimal("20.00"), approved_payee=PAYEE)


def failed(decision) -> set:
    return {check.name for check in decision.failed_checks}


def test_legitimate_payment_is_allowed():
    decision = evaluate(POLICY, LEGIT, APPROVAL)
    assert decision.allowed
    assert failed(decision) == set()


def test_check_names_and_order_match_the_frontend():
    decision = evaluate(POLICY, LEGIT, APPROVAL)
    assert [c.name for c in decision.checks] == [
        "Amount ≤ authorized amount",
        "Amount ≤ spending limit",
        "Explicit user approval",
        "Approved amount matches order",
        "Payee on allowlist",
    ]


# The three attacks from the payment lab.


def test_amount_inflation_is_denied():
    proposal = PaymentProposal(amount=Decimal("200.00"), payee=PAYEE)
    decision = evaluate(POLICY, proposal, APPROVAL)
    assert not decision.allowed
    assert failed(decision) == {
        CHECK_AUTHORIZED_AMOUNT,
        CHECK_SPENDING_LIMIT,
        CHECK_APPROVED_AMOUNT,
    }


def test_approval_bypass_is_denied():
    decision = evaluate(POLICY, LEGIT, approval=None)
    assert not decision.allowed
    assert failed(decision) == {CHECK_APPROVAL}


def test_payee_swap_is_denied():
    proposal = PaymentProposal(amount=Decimal("20.00"), payee=ATTACKER)
    decision = evaluate(POLICY, proposal, APPROVAL)
    assert not decision.allowed
    assert failed(decision) == {CHECK_PAYEE}


# Individual checks.


def test_amount_below_authorized_is_allowed_without_approval_if_not_required():
    policy = PaymentPolicy.create(
        Decimal("20.00"), Decimal("50.00"), require_approval=False, payee_allowlist=[PAYEE]
    )
    proposal = PaymentProposal(amount=Decimal("15.00"), payee=PAYEE)
    assert evaluate(policy, proposal).allowed


def test_spending_limit_applies_even_when_user_authorized_more():
    policy = PaymentPolicy.create(
        Decimal("100.00"), Decimal("50.00"), require_approval=False, payee_allowlist=[PAYEE]
    )
    proposal = PaymentProposal(amount=Decimal("80.00"), payee=PAYEE)
    assert failed(evaluate(policy, proposal)) == {CHECK_SPENDING_LIMIT}


def test_approval_for_a_different_amount_is_denied():
    proposal = PaymentProposal(amount=Decimal("19.00"), payee=PAYEE)
    decision = evaluate(POLICY, proposal, APPROVAL)
    assert failed(decision) == {CHECK_APPROVED_AMOUNT}


def test_approval_for_a_different_allowlisted_payee_is_denied():
    other = "billing@acme-saas.example"
    policy = PaymentPolicy.create(
        Decimal("20.00"), Decimal("50.00"), True, payee_allowlist=[PAYEE, other]
    )
    proposal = PaymentProposal(amount=Decimal("20.00"), payee=other)
    decision = evaluate(policy, proposal, APPROVAL)
    assert failed(decision) == {CHECK_PAYEE}


def test_payee_matching_ignores_case_and_surrounding_spaces():
    proposal = PaymentProposal(amount=Decimal("20.00"), payee="  Merchant@ACME-saas.example ")
    assert evaluate(POLICY, proposal, APPROVAL).allowed


def test_lookalike_payee_is_denied():
    proposal = PaymentProposal(amount=Decimal("20.00"), payee="merchant@acme-saas.example.evil")
    assert failed(evaluate(POLICY, proposal, APPROVAL)) == {CHECK_PAYEE}


# Fail closed on malformed input.


@pytest.mark.parametrize(
    "amount",
    [Decimal("0"), Decimal("-20.00"), Decimal("19.999"), Decimal("NaN"), Decimal("Infinity"), Decimal("1E+30"), 20.0, "20.00", None],
)
def test_malformed_amounts_are_denied_without_raising(amount):
    proposal = PaymentProposal(amount=amount, payee=PAYEE)
    decision = evaluate(POLICY, proposal, APPROVAL)
    assert not decision.allowed
    assert {CHECK_AUTHORIZED_AMOUNT, CHECK_SPENDING_LIMIT} <= failed(decision)


def test_negative_amount_cannot_slip_under_the_limits():
    proposal = PaymentProposal(amount=Decimal("-500.00"), payee=PAYEE)
    assert not evaluate(POLICY, proposal, None).allowed


def test_non_usd_currency_is_denied():
    proposal = PaymentProposal(amount=Decimal("20.00"), payee=PAYEE, currency="EUR")
    decision = evaluate(POLICY, proposal, APPROVAL)
    assert not decision.allowed
    assert CHECK_AUTHORIZED_AMOUNT in failed(decision)


@pytest.mark.parametrize("authorized", [Decimal("NaN"), Decimal("1E+30")])
def test_invalid_policy_denies_everything(authorized):
    policy = PaymentPolicy.create(authorized, Decimal("50.00"), False, [PAYEE])
    assert not evaluate(policy, LEGIT).allowed


def test_empty_allowlist_denies_everything():
    policy = PaymentPolicy.create(Decimal("20.00"), Decimal("50.00"), False, [])
    assert failed(evaluate(policy, LEGIT)) == {CHECK_PAYEE}


def test_non_string_payee_is_denied():
    proposal = PaymentProposal(amount=Decimal("20.00"), payee=None)
    assert CHECK_PAYEE in failed(evaluate(POLICY, proposal, APPROVAL))


def test_details_explain_each_failure():
    proposal = PaymentProposal(amount=Decimal("200.00"), payee=ATTACKER)
    details = {c.name: c.detail for c in evaluate(POLICY, proposal, None).checks}
    assert details[CHECK_AUTHORIZED_AMOUNT] == "$200.00 vs authorized $20.00"
    assert details[CHECK_SPENDING_LIMIT] == "$200.00 vs limit $50.00"
    assert details[CHECK_APPROVAL] == "No user approval present"
    assert details[CHECK_PAYEE] == f"{ATTACKER} is not on the allowlist"
