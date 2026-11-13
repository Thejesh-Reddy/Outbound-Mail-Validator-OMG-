"""Explainable detection for common outbound-email fraud and phishing patterns.

A category is emitted only when related indicators form a meaningful pattern.
Strong combinations are confirmed HIGH/CRITICAL findings and therefore enter
OMG's existing RESTRICTED decision path. Single weak words are not sufficient.
"""
from __future__ import annotations
import re
from bs4 import BeautifulSoup

SCAM_CATEGORIES = [
    "ADVANCE_FEE_SCAM", "LOTTERY_SCAM", "FAKE_GIVEAWAY_SCAM",
    "TAX_REFUND_PHISHING", "LOAN_SCAM", "FINANCIAL_FRAUD",
    "IDENTITY_THEFT", "PERSONAL_INFORMATION_HARVESTING",
    "CREDENTIAL_HARVESTING", "URGENCY_MANIPULATION", "REWARD_DECEPTION",
    "INVESTMENT_SCAM", "CRYPTOCURRENCY_SCAM", "ROMANCE_SCAM",
    "JOB_FEE_SCAM", "FAKE_DONATION_SCAM", "INVOICE_PAYMENT_FRAUD",
    "BUSINESS_EMAIL_COMPROMISE", "CEO_IMPERSONATION", "VENDOR_IMPERSONATION",
    "ACCOUNT_TAKEOVER", "ACCOUNT_SUSPENSION_PHISHING", "DELIVERY_FEE_SCAM",
    "SUBSCRIPTION_RENEWAL_PHISHING", "TECH_SUPPORT_SCAM", "GIFT_CARD_SCAM",
    "EXTORTION_SCAM", "SEXTORTION_SCAM", "QR_CODE_PHISHING",
    "MFA_CODE_HARVESTING", "PAYMENT_REDIRECTION", "BANKING_PHISHING",
    "FAKE_INHERITANCE_SCAM", "UNSOLICITED_PROMOTIONAL_SPAM",
]


def _has(pattern: str, text: str) -> bool:
    return bool(re.search(pattern, text, re.I | re.S))


def _text(subject: str, body: str, html: str) -> str:
    visible = BeautifulSoup("\n".join((body or "", html or "")), "html.parser").get_text(" ", strip=True)
    # Include href destinations as evidence; they are separately checked by URL module.
    soup = BeautifulSoup(html or "", "html.parser")
    hrefs = " ".join(str(a.get("href", "")) for a in soup.find_all("a", href=True))
    return re.sub(r"\s+", " ", f"{subject or ''} {visible} {hrefs}")[:150_000]


def inspect_fraud_patterns(subject: str, body: str = "", html: str = "") -> list[dict]:
    t = _text(subject, body, html)
    if not t.strip():
        return []

    # Educational/security-awareness messages should not be treated as live lures.
    awareness = _has(
        r"\b(?:security awareness|phishing awareness|scam awareness|fraud prevention|"
        r"how to (?:spot|recognize|report|avoid) (?:a )?(?:scam|phishing)|"
        r"example of (?:a )?(?:phishing|scam|fraud))\b", t
    )

    findings: list[dict] = []
    seen: set[str] = set()

    def add(code: str, severity: str, message: str, *, confirmed: bool = True, confidence: float = 0.94):
        if code in seen:
            return
        seen.add(code)
        findings.append({
            "code": code,
            "category": code,
            "severity": severity,
            "confidence": confidence,
            "confirmed": confirmed,
            "message": message,
        })

    if awareness:
        return findings

    # Shared evidence primitives.
    prize = _has(r"\b(?:voucher|gift\s*card|prize|reward|giveaway|sweepstakes|lottery|winner|won|selected|promotional campaign)\b", t)
    winner = _has(r"\b(?:you have been selected|you(?:'| a)?ve been selected|you have won|congratulations|dear winner|exclusive reward|won an?)\b", t)
    advance_fee = _has(r"\b(?:activation|processing|administrative|release|handling|registration|verification|delivery|customs?)\s+fee\b|\bupfront\s+(?:payment|fee|charge)\b|\bpay\b.{0,100}\b(?:fee|charge)\b", t)
    unlock_or_release = _has(r"\b(?:unlock|activate|release|claim|collect|receive|disburse|process)\b", t)
    sensitive_request = _has(r"\b(?:submit|provide|send|upload|enter|share)\b.{0,220}\b(?:personal information|bank(?:ing)? (?:information|details|account)|account number|routing number|payment details|credit card|debit card|identity documents?|proof of identity|passport|national id|aadhaar|aadhar|pan card|date of birth|residential address|phone number)\b", t)
    urgency = _has(r"\b(?:within\s+\d+\s+hours?|\d+\s+hours?\s+only|today only|expires? today|immediately|urgent(?:ly)?|final notice|last chance|only\s+\d+\s+(?:remaining|left)|limited time)\b", t)
    money = _has(r"(?:[$€£₹]\s?\d[\d,]*(?:\.\d{2})?|\b\d[\d,]*(?:\.\d{2})?\s?(?:usd|dollars?|euros?|pounds?)\b)", t)

    # 1) Prize / voucher / lottery / giveaway + fee to unlock or receive.
    if prize and (winner or _has(r"\bfree\b.{0,50}\b(?:voucher|gift\s*card|prize|reward)\b", t)) and advance_fee and unlock_or_release:
        add("ADVANCE_FEE_SCAM", "CRITICAL", "A promised prize, voucher or reward is conditional on paying an activation, processing or release fee.")
        add("REWARD_DECEPTION", "HIGH", "A high-value reward claim is paired with a payment condition.", confirmed=False, confidence=0.4)
        if _has(r"\b(?:lottery|sweepstakes|jackpot|raffle)\b", t):
            add("LOTTERY_SCAM", "CRITICAL", "A lottery or prize-winning claim requires an advance payment.")
        else:
            add("FAKE_GIVEAWAY_SCAM", "HIGH", "A promotional giveaway or voucher claim requires an advance payment.", confirmed=False, confidence=0.4)

    # 2) Fake prize/gift claim + request for payment or personal data.
    if prize and winner and sensitive_request:
        if _has(r"\b(?:gift\s*card|smartphone|iphone|phone)\b", t):
            add("FAKE_GIVEAWAY_SCAM", "CRITICAL", "An unsolicited gift or device award requests sensitive recipient information.")
        add("PERSONAL_INFORMATION_HARVESTING", "HIGH", "A purported prize or giveaway requests personal, identity or financial information.", confirmed=False, confidence=0.4)
        add("IDENTITY_THEFT", "HIGH", "Identity or financial data is requested as a condition of receiving an unsolicited reward.", confirmed=False, confidence=0.4)

    # 3) Tax refund impersonation.
    tax = _has(r"\b(?:tax refund|taxpayer refund|tax rebate|revenue department|tax authority|irs|hmrc)\b", t)
    refund = _has(r"\b(?:refund|rebate)\b", t)
    bank_or_id = _has(r"\b(?:bank(?:ing)? (?:information|details|account)|account number|routing number|identification documents?|identity documents?|passport|national id|aadhaar|aadhar|pan (?:card|number)|personal information)\b", t)
    verify_or_submit = _has(r"\b(?:verify|verification|submit|provide|update|confirm|upload)\b", t)
    if tax and refund and bank_or_id and verify_or_submit:
        add("TAX_REFUND_PHISHING", "CRITICAL", "A tax-refund message requests banking or identity information to release a claimed refund.")
        add("BANKING_PHISHING", "HIGH", "A refund-themed message requests sensitive banking information.", confirmed=False, confidence=0.4)
        add("IDENTITY_THEFT", "HIGH", "A tax-refund pretext is used to solicit identity information.", confirmed=False, confidence=0.4)
        add("PERSONAL_INFORMATION_HARVESTING", "HIGH", "Personal or financial information is requested under a tax-refund pretext.", confirmed=False, confidence=0.4)
    elif refund and bank_or_id and urgency and verify_or_submit:
        add("FINANCIAL_FRAUD", "HIGH", "An urgent refund message requests sensitive banking or identity data.")

    # 4) Advance-fee loan fraud.
    loan = _has(r"\b(?:loan|credit|cash advance|personal loan|financing)\b", t)
    loan_promise = _has(r"\b(?:pre[- ]?approved|guaranteed approval|instant approval|100\s*%\s*guaranteed|approved regardless|no credit check)\b", t)
    loan_fee = advance_fee or _has(r"\b(?:pay|deposit|transfer|send)\b.{0,80}\b(?:processing|insurance|release|application|upfront)\s+fee\b", t)
    if loan and loan_promise and loan_fee:
        add("LOAN_SCAM", "CRITICAL", "A guaranteed or no-check loan approval is conditional on an upfront fee.")
        add("ADVANCE_FEE_SCAM", "HIGH", "An upfront fee is demanded before a promised loan is released.", confirmed=False, confidence=0.4)
        add("FINANCIAL_FRAUD", "HIGH", "The loan offer uses an upfront payment condition and unrealistic approval claims.", confirmed=False, confidence=0.4)
    elif loan and loan_promise and _has(r"\b(?:no employment verification|no paperwork|regardless of your financial history)\b", t):
        add("LOAN_SCAM", "HIGH", "A loan offer makes implausible guaranteed-approval claims while bypassing normal checks.")

    # 5) Credential/account takeover and MFA theft.
    credentials = _has(r"\b(?:password|login credentials?|username|otp|one[- ]time (?:password|code)|verification code|mfa code|2fa code|authentication code)\b", t)
    credential_action = _has(r"\b(?:submit|enter|provide|share|send|reply with|verify|confirm)\b", t)
    account_pressure = _has(r"\b(?:account|mailbox|profile|online banking|wallet)\b.{0,80}\b(?:suspend|lock|disable|close|restrict|expire|verify)\b|\b(?:suspend|lock|disable|close)\b.{0,60}\baccount\b", t)
    if credentials and credential_action and (account_pressure or urgency or _has(r"\b(?:click|visit|open)\b.{0,60}\b(?:link|button|portal|page)\b", t)):
        add("CREDENTIAL_HARVESTING", "CRITICAL", "The message requests authentication secrets using an account-verification or urgency pretext.")
        add("ACCOUNT_TAKEOVER", "HIGH", "Credentials or one-time authentication codes are solicited in a suspicious message.")
        if _has(r"\b(?:otp|one[- ]time (?:password|code)|mfa code|2fa code|verification code)\b", t):
            add("MFA_CODE_HARVESTING", "CRITICAL", "A one-time or multi-factor authentication code is requested.")
    if account_pressure and (urgency or _has(r"\b(?:verify|confirm|update)\b", t)) and _has(r"\b(?:click|link|login|sign in|password|credentials?)\b", t):
        add("ACCOUNT_SUSPENSION_PHISHING", "HIGH", "An account suspension or verification threat is used to drive a login or link action.")

    # 6) Invoice / supplier / executive impersonation and payment redirection.
    payment = _has(r"\b(?:invoice|payment|wire transfer|bank transfer|remittance|purchase order|vendor payment|supplier payment)\b", t)
    changed_bank = _has(r"\b(?:new|updated|changed|revised|replacement)\b.{0,70}\b(?:bank|account|payment)\b.{0,50}\b(?:details|information|instructions|number)\b|\b(?:bank|account|payment)\b.{0,60}\b(?:details|information)\b.{0,40}\b(?:changed|updated|new)\b", t)
    payment_action = _has(r"\b(?:pay|transfer|wire|send|remit|settle)\b", t)
    if payment and changed_bank and payment_action:
        add("PAYMENT_REDIRECTION", "CRITICAL", "Payment instructions or bank details are changed and the recipient is asked to transfer funds.")
        add("INVOICE_PAYMENT_FRAUD", "HIGH", "An invoice or payment workflow contains changed banking instructions.")
        add("BUSINESS_EMAIL_COMPROMISE", "HIGH", "The message exhibits a supplier or business-payment redirection pattern.")
    executive = _has(r"\b(?:ceo|chief executive|managing director|finance director|cfo|company director)\b", t)
    secrecy = _has(r"\b(?:keep this confidential|do not tell|don't tell|secret|discreetly|without informing)\b", t)
    if executive and payment_action and (urgency or secrecy):
        add("CEO_IMPERSONATION", "HIGH", "An executive identity is invoked to pressure an urgent or secret payment.")
        add("BUSINESS_EMAIL_COMPROMISE", "HIGH", "The message resembles executive impersonation or business-email-compromise fraud.")

    # 7) Delivery/customs fee lures.
    delivery = _has(r"\b(?:parcel|package|shipment|delivery|courier|customs)\b", t)
    delivery_fee = _has(r"\b(?:delivery|redelivery|customs|handling)\s+fee\b|\bpay\b.{0,70}\b(?:delivery|customs)\s+fee\b", t)
    if delivery and delivery_fee and (urgency or _has(r"\b(?:track|release|deliver|reschedule)\b", t)):
        add("DELIVERY_FEE_SCAM", "HIGH", "A parcel or delivery notice demands an unexpected fee to release or reschedule delivery.")
        add("ADVANCE_FEE_SCAM", "HIGH", "A payment is demanded before a promised delivery service is completed.")

    # 8) Employment/job fee fraud.
    job = _has(r"\b(?:job offer|work from home|remote position|vacancy|recruitment|hiring|employment opportunity|you are hired|job placement)\b", t)
    job_fee = _has(r"\b(?:registration|training|equipment|interview|placement|processing)\s+fee\b", t)
    if job and job_fee and _has(r"\b(?:pay|deposit|transfer|purchase)\b", t):
        add("JOB_FEE_SCAM", "HIGH", "An employment opportunity requires an upfront recruitment, training or equipment payment.")
        add("ADVANCE_FEE_SCAM", "HIGH", "An upfront payment is tied to a promised job or employment benefit.")

    # 9) Investment / crypto scams.
    investment = _has(r"\b(?:investment|invest|crypto(?:currency)?|bitcoin|ethereum|trading platform|forex)\b", t)
    guaranteed_returns = _has(r"\b(?:guaranteed|risk[- ]free|no risk)\b.{0,80}\b(?:profit|returns?|income|earnings?)\b|\b(?:profit|returns?|income)\b.{0,50}\bguaranteed\b", t)
    if investment and guaranteed_returns and (urgency or _has(r"\b(?:deposit|send|transfer|wallet address|connect wallet)\b", t)):
        add("INVESTMENT_SCAM", "CRITICAL", "An investment offer promises guaranteed returns and pressures the recipient to act or transfer funds.")
        if _has(r"\b(?:crypto|bitcoin|ethereum|wallet)\b", t):
            add("CRYPTOCURRENCY_SCAM", "HIGH", "A cryptocurrency-related offer uses guaranteed-return or urgent-funding claims.")
        add("FINANCIAL_FRAUD", "HIGH", "The investment message contains high-risk financial solicitation indicators.")

    # 10) Extortion/sextortion.
    extortion = _has(r"\b(?:pay|send|transfer)\b.{0,100}\b(?:or else|otherwise|unless)\b|\b(?:ransom|blackmail|extort)\b", t)
    threat = _has(r"\b(?:i have your (?:password|data|photos|videos)|i will (?:expose|publish|leak|share)|we will expose)\b", t)
    intimate = _has(r"\b(?:intimate photos?|private photos?|explicit videos?|webcam footage|nudes?)\b", t)
    if extortion and threat:
        add("EXTORTION_SCAM", "CRITICAL", "The message threatens exposure or harm unless money is paid.")
        if intimate:
            add("SEXTORTION_SCAM", "CRITICAL", "The extortion threat involves intimate images or sexual material.")

    # 11) Subscription renewal / tech-support lures.
    subscription = _has(r"\b(?:subscription|membership|renewal|billing plan)\b", t)
    if subscription and _has(r"\b(?:payment failed|renewal failed|cancel immediately|call support|refund)\b", t) and _has(r"\b(?:click|call|provide|update|verify)\b", t):
        add("SUBSCRIPTION_RENEWAL_PHISHING", "HIGH", "A subscription or renewal notice pushes the recipient to click, call or disclose payment information.")
    tech = _has(r"\b(?:technical support|tech support|microsoft support|apple support|computer infected|virus detected|device compromised)\b", t)
    if tech and _has(r"\b(?:call|pay|install|download|grant remote|remote access)\b", t):
        add("TECH_SUPPORT_SCAM", "HIGH", "A technical-support warning asks the recipient to pay, install software or grant remote access.")

    # 12) Charity / donation pretext.
    charity = _has(r"\b(?:charity|donation|disaster relief|humanitarian aid|fundraiser|救援)\b", t)
    if charity and _has(r"\b(?:urgent|emergency|victims|relief)\b", t) and _has(r"\b(?:wire|transfer|crypto|wallet|send money|donate now)\b", t):
        add("FAKE_DONATION_SCAM", "HIGH", "An urgent charitable appeal requests direct or difficult-to-reverse payments without verified context.")

    # 12b) Inheritance, romance, vendor and gift-card payment scams.
    inheritance = _has(r"\b(?:inheritance|inherited funds|estate funds|unclaimed inheritance|next of kin|beneficiary)\b", t)
    if inheritance and advance_fee and (sensitive_request or unlock_or_release):
        add("FAKE_INHERITANCE_SCAM", "CRITICAL", "An alleged inheritance or estate payment requires an advance fee or sensitive information.")
        add("ADVANCE_FEE_SCAM", "CRITICAL", "A fee is demanded before alleged inheritance funds are released.")

    romance = _has(r"\b(?:online relationship|dating|romantic partner|lover|i love you|soulmate)\b", t)
    romance_emergency = _has(r"\b(?:emergency|hospital|stranded|stuck abroad|customs|visa|ticket|medical bills?)\b", t)
    romance_payment = _has(r"\b(?:send|transfer|wire|pay|buy)\b.{0,80}\b(?:money|cash|gift cards?|bitcoin|crypto|ticket|fee)\b", t)
    if romance and romance_emergency and romance_payment:
        add("ROMANCE_SCAM", "CRITICAL", "A relationship or romantic pretext is combined with an emergency story and a request for money or gift cards.")
        add("ADVANCE_FEE_SCAM", "HIGH", "Payment is requested to resolve a claimed personal emergency.")

    gift_payment = _has(r"\b(?:buy|purchase|send|pay with|pay using)\b.{0,70}\b(?:gift cards?|itunes cards?|google play cards?|steam cards?)\b", t)
    gift_code = _has(r"\b(?:send|share|read|provide|reveal)\b.{0,60}\b(?:gift card|redemption)\s*(?:code|number)s?\b", t)
    if gift_payment or gift_code:
        add("GIFT_CARD_SCAM", "HIGH", "The recipient is instructed to pay with gift cards or disclose redemption codes.")
        if urgency or secrecy:
            add("FINANCIAL_FRAUD", "HIGH", "Gift-card payment instructions are paired with pressure or secrecy.")

    vendor_context = _has(r"\b(?:vendor|supplier|accounts payable|purchase order|invoice)\b", t)
    if vendor_context and changed_bank and payment_action:
        add("VENDOR_IMPERSONATION", "HIGH", "A vendor or supplier payment context contains changed bank details and a payment instruction.")

    qr_prompt = _has(r"\b(?:scan|open)\b.{0,45}\b(?:qr code|qr)\b|\bqr code\b.{0,60}\b(?:login|verify|payment|account|credentials?)\b", t)
    if qr_prompt and (credentials or account_pressure or payment_action):
        add("QR_CODE_PHISHING", "HIGH", "A QR-code action is connected to login, account verification or payment activity.")

    # Generic unsolicited bulk/promotional spam is a review signal, not an
    # automatic block, unless a stronger fraud detector above also matches.
    bulk_promo = _has(r"\b(?:unsubscribe|promotional offer|special offer|limited time offer|buy now)\b", t)
    if bulk_promo and _has(r"\b(?:free|discount|deal|offer|sale)\b", t) and not (prize and advance_fee):
        add("UNSOLICITED_PROMOTIONAL_SPAM", "MEDIUM", "The message has unsolicited bulk-promotional characteristics; sender consent and reputation should be checked.", confirmed=False, confidence=0.55)

    # 13) Urgency manipulation is a supporting category only when paired with an action.
    action = _has(r"\b(?:click|pay|transfer|submit|verify|provide|upload|reply|call)\b", t)
    if urgency and action and (sensitive_request or advance_fee or account_pressure or payment or prize):
        add("URGENCY_MANIPULATION", "MEDIUM", "A deadline or scarcity claim is used to pressure a sensitive action.", confirmed=False, confidence=0.5)

    # If the content shows a suspicious request for sensitive data but not enough
    # evidence for a named pretext, preserve it as a high-severity review finding.
    if sensitive_request and (urgency or _has(r"\b(?:prize|refund|loan|account|verification|winner)\b", t)):
        add("PERSONAL_INFORMATION_HARVESTING", "HIGH", "The message requests personal or financial data in a pressured or suspicious context.")

    return findings
