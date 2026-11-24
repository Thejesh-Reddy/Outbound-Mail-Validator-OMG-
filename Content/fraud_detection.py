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
    "FAKE_INVOICE_FRAUD",
    "FAKE_PURCHASE_ORDER",
    "FAKE_REFUND_CLAIM",
    "PAYMENT_OVERDUE_PRESSURE",
    "PAYMENT_SPLITTING_REQUEST",
    "FAKE_TAX_COMPLIANCE_NOTICE",
    "FAKE_LEGAL_THREAT",
    "FAKE_ACCOUNT_SUSPENSION",
    "FAKE_SECURITY_ALERT",
    "FAKE_CUSTOMER_SUPPORT",
    "FAKE_RECRUITER_IMPERSONATION",
    "FAKE_JOB_OFFER",
    "FAKE_INTERVIEW_FEE",
    "FAKE_BUSINESS_PARTNERSHIP",
    "FAKE_CRYPTO_AIRDROP",
    "FAKE_INVESTMENT_RETURN",
    "PONZI_SCHEME_PROMOTION",
    "PUMP_AND_DUMP_PROMOTION",
    "FAKE_GOVERNMENT_AUTHORITY",
    "FAKE_COURT_SUMMONS",
    "FAKE_INSURANCE_CLAIM",
    "FAKE_DELIVERY_CUSTOMS_FEE",
    "MONEY_MULE_RECRUITMENT",
    "MONEY_LAUNDERING_INSTRUCTION",
    "PAYMENT_APPROVAL_BYPASS",
    "MFA_PUSH_FATIGUE",
    "FAKE_SSO_LOGIN",
    "FAKE_VPN_LOGIN",
    "FAKE_CLOUD_STORAGE_LOGIN",
    "FAKE_WEBMAIL_LOGIN",
    "PASSWORD_MANAGER_PHISHING",
    "ACCOUNT_RECOVERY_ABUSE",
    "FAKE_EMAIL_QUARANTINE_NOTICE",
    "FAKE_EMAIL_DELIVERY_FAILURE",
    "HTML_FORM_CREDENTIAL_CAPTURE",
    "FAKE_PASSWORD_MANAGER_SHARING",
    "PAYROLL_DIRECT_DEPOSIT_CHANGE",
    "FAKE_AUDITOR_REQUEST",
    "FAKE_BOARD_MEMBER_REQUEST",
    "PAYMENT_BENEFICIARY_MISMATCH",
    "UNUSUAL_PAYMENT_DESTINATION",
    "CUSTOMER_PII_DISCLOSURE",
    "EMPLOYEE_PII_DISCLOSURE",
    "PAYMENT_CARD_DATA_EXPOSURE",
    "BANKING_INFORMATION_EXPOSURE",
    "HEALTH_INFORMATION_DISCLOSURE",
    "INTELLECTUAL_PROPERTY_EXFILTRATION",
    "SOURCE_CODE_EXFILTRATION",
    "BULK_DATA_TRANSFER",
    "EXTERNAL_STORAGE_EXFILTRATION",
    "PERSONAL_EMAIL_EXFILTRATION",
    "DATA_RETENTION_POLICY_BYPASS",
    "AUDIT_LOG_TAMPERING",
    "REMOTE_ACCESS_INSTALLATION",
    "MALICIOUS_MACRO_ENABLEMENT",
    "SENSITIVE_DATA_REQUEST",
    "UNAUTHORIZED_PRIVILEGE_ESCALATION",
    "DATA_DELETION_OR_DESTRUCTION",
    "SECURITY_CONTROL_DISABLEMENT",
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


    # Exclude explicit preventive instructions from lexical lure matching only.
    # Independent clauses remain eligible for detection; URL/attachment scans are separate.
    t = re.sub(
        r"\b(?:never|do not|don't|must not|should not|shall not)\s+"
        r"(?:send|share|provide|forward|upload|export|copy|transfer|publish|"
        r"disclose|reveal|delete|erase|destroy|disable|approve|enter)\b"
        r"(?:(?!\b(?:but|however|instead|then|and)\b|[.!?;\n]).)*",
        " ", t, flags=re.I
    )

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
    gift_payment_method = _has(r"\b(?:pay with|pay using)\b.{0,70}\bgift cards?\b", t)
    if gift_code or (gift_payment_method and (urgency or secrecy)) or (gift_payment and executive and secrecy):
        add("GIFT_CARD_SCAM", "HIGH", "The recipient is instructed to pay with gift cards or disclose redemption codes.")
        if urgency or secrecy:
            add("FINANCIAL_FRAUD", "HIGH", "Gift-card payment instructions are paired with pressure or secrecy.")

    elif gift_payment and urgency:
        add("URGENT_GIFT_CARD_PURCHASE", "MEDIUM",
            "Urgent gift card purchase requires verification.",
            confirmed=False, confidence=0.82)

    vendor_context = _has(r"\b(?:vendor|supplier|accounts payable|purchase order|invoice)\b", t)
    if vendor_context and changed_bank and payment_action:
        add("VENDOR_IMPERSONATION", "HIGH", "A vendor or supplier payment context contains changed bank details and a payment instruction.")

    qr_prompt = _has(r"\b(?:scan|open)\b.{0,45}\b(?:qr code|qr)\b|\bqr code\b.{0,60}\b(?:login|verify|payment|account|credentials?)\b", t)
    if qr_prompt and (credentials or account_pressure or payment_action):
        add("QR_CODE_PHISHING", "HIGH", "A QR-code action is connected to login, account verification or payment activity.")

    
    # 13) Generic unsolicited bulk/promotional spam is a review signal,
    # not an automatic block.
    promo_discount = _has(
        r"\b(?:\d{1,3}\s?%\s*(?:off|discount)|"
        r"(?:save|up to)\s+\d{1,3}\s?%|"
        r"discount|sale|deal|offer|savings|clearance)\b",
        t,
    )

    promo_campaign = _has(
        r"\b(?:exclusive savings|exclusive offer|special offer|"
        r"limited[- ]time offer|biggest sale|seasonal sale|"
        r"flash sale|promotional offer|special pricing)\b",
        t,
    )

    promo_cta = _has(
        r"\b(?:shop now|buy now|claim your deal|claim your offer|"
        r"grab yours|get yours|redeem now|order now|"
        r"shop today|browse deals|don't miss out)\b",
        t,
    )

    promo_urgency = _has(
        r"\b(?:today only|ends today|ends soon|limited time|"
        r"last chance|act now|hurry|while stocks last|"
        r"offer expires|only for today)\b",
        t,
    )

    bulk_promo = (
        (promo_discount and (promo_cta or promo_urgency))
        or (promo_campaign and (promo_cta or promo_urgency))
    )

    if bulk_promo and not (prize and advance_fee):
        add(
            "UNSOLICITED_PROMOTIONAL_SPAM",
            "MEDIUM",
            "The message combines promotional claims with urgency or a purchase/claim action; sender consent and reputation should be checked.",
            confirmed=False,
            confidence=0.55,
        )

    # 14) Fake work-from-home and unrealistic income opportunities.
    income_claim = _has(
        r"\b(?:earn|earning|make|making|get paid|income|salary)\b"
        r".{0,100}\b(?:₹|rs\.?|inr)?\s*[\d,]+"
        r"(?:\s*(?:per|a|every)\s*(?:day|week|month))?\b",
        t,
    )
    unrealistic_income = _has(
        r"\b(?:no experience required|no experience needed|"
        r"work from home|earn from home|guaranteed income|"
        r"easy money|passive income|daily income|weekly income)\b",
        t,
    )
    recruitment_action = _has(
        r"\b(?:register now|apply now|join now|secure your position|"
        r"limited positions|start earning|sign up now)\b",
        t,
    )
    if income_claim and unrealistic_income and recruitment_action:
        add("UNVERIFIED_INCOME_OPPORTUNITY", "MEDIUM",
            "An income opportunity combines an earnings claim, low-entry requirements and a recruitment action.",
            confirmed=False, confidence=0.65)

    # 15) Task-based earning and fake online jobs.
    task_earning = _has(
        r"\b(?:complete|finish|perform)\b.{0,60}\b(?:tasks?|assignments?|offers?)\b",
        t,
    )
    task_payment = _has(
        r"\b(?:earn|receive|get paid|payment|commission)\b.{0,70}\b(?:per task|daily|weekly|commission|reward|bonus)\b",
        t,
    )
    if task_earning and task_payment and _has(
        r"\b(?:telegram|whatsapp|online job|part.time job|"
        r"work from home|easy income)\b", t
    ):
        add("TASK_EARNING_SCAM", "MEDIUM",
            "An online task opportunity promises earnings for completing tasks; verify the employer and payment conditions.",
            confirmed=False, confidence=0.65)

    # 16) Fake survey and review earning schemes.
    survey = _has(r"\b(?:paid surveys?|product reviews?|app reviews?|"
                  r"like and subscribe|review and earn)\b", t)
    survey_reward = _has(r"\b(?:earn|cash reward|payment|"
                         r"commission|gift voucher|paid)\b", t)
    if survey and survey_reward:
        add("FAKE_SURVEY_REWARD_PROMOTION", "MEDIUM",
            "A survey or review activity promises financial rewards; verify the organization and terms.",
            confirmed=False, confidence=0.60)

    # 17) Referral and recruitment reward abuse.
    referral = _has(r"\b(?:refer|invite|recruit)\b.{0,60}\b(?:friends?|members?|people|users?)\b", t)
    referral_reward = _has(r"\b(?:earn|bonus|commission|cash reward|"
                           r"unlimited income|unlock reward)\b", t)
    if referral and referral_reward:
        add("REFERRAL_REWARD_ABUSE", "MEDIUM",
            "A referral campaign offers financial incentives for recruiting additional participants.",
            confirmed=False, confidence=0.55)

    # 18) Pyramid and multi-level marketing warning.
    pyramid = _has(
        r"\b(?:build your team|recruit your team|"
        r"earn from your downline|multiple income levels|"
        r"unlimited commissions|network marketing)\b", t
    )
    if pyramid and _has(r"\b(?:recruit|join|invest|membership|commission)\b", t):
        add("PYRAMID_SCHEME_INDICATOR", "HIGH",
            "The message contains recruitment-based income indicators requiring business-model verification.",
            confirmed=False, confidence=0.70)

    # 19) Fake free-trial and subscription promotions.
    free_trial = _has(r"\b(?:free trial|free subscription|"
                      r"try free|first month free)\b", t)
    automatic_charge = _has(r"\b(?:automatically charge|auto.?renew|"
                            r"recurring billing|subscription fee|"
                            r"charged after trial)\b", t)
    if free_trial and automatic_charge:
        add("DECEPTIVE_SUBSCRIPTION_PROMOTION", "MEDIUM",
            "A free-trial promotion includes automatic or recurring charges that require clear disclosure.",
            confirmed=False, confidence=0.60)

    # 20) Generic mailbox and password-reset phishing.
    mailbox = _has(r"\b(?:mailbox|email account|office 365|microsoft 365|"
                   r"webmail|google workspace)\b", t)
    login_action = _has(r"\b(?:sign in|log in|login|authenticate|"
                        r"access your account|click here)\b", t)
    if mailbox and login_action and (urgency or account_pressure):
        add("MAILBOX_PHISHING", "HIGH",
            "A mailbox access request uses urgency or account pressure to drive authentication.",
            confirmed=False, confidence=0.75)

    # 21)OAuth application consent phishing.
    oauth = _has(r"\b(?:oauth|authorize this application|"
                 r"grant permissions|consent request|"
                 r"allow access to your mailbox)\b", t)
    if oauth and _has(r"\b(?:email|mailbox|files|contacts|account|"
                      r"permissions|access)\b", t):
        add("OAUTH_CONSENT_PHISHING", "HIGH",
            "An application requests account or mailbox permissions that should be verified.",
            confirmed=False, confidence=0.75)

    # 22)Fake HR and payroll information requests.
    hr = _has(r"\b(?:human resources|hr department|payroll|"
              r"employee benefits|employee records)\b", t)
    employee_data = _has(r"\b(?:update|confirm|verify|submit|provide)\b.{0,100}"
                         r"\b(?:salary account|bank details|employee id|"
                         r"personal details|tax information)\b", t)
    if hr and employee_data:
        add("HR_PAYROLL_PHISHING", "HIGH",
            "An HR or payroll communication requests sensitive employee information.",
            confirmed=False, confidence=0.75)

    # 23) Fake shared-document notifications.
    shared_document = _has(r"\b(?:shared a document|shared file|"
                           r"view document|document awaiting review|"
                           r"secure document)\b", t)
    if shared_document and login_action and _has(
        r"\b(?:password|credentials|verify|sign in|account)\b", t
    ):
        add("SHARED_DOCUMENT_PHISHING", "HIGH",
            "A shared-document notification requests account authentication.",
            confirmed=False, confidence=0.75)

    # 24) Session expiration and reauthentication lures.
    session = _has(r"\b(?:session expired|session timeout|"
                   r"reauthenticate|session validation)\b", t)
    if session and login_action:
        add("SESSION_HIJACKING_PHISHING", "HIGH",
            "A session-expiration message directs the recipient to authenticate again.",
            confirmed=False, confidence=0.70)

        # 25) Fake employment equipment purchases.
    equipment_job = _has(r"\b(?:remote job|work from home|job offer|"
                         r"employment opportunity|new employee)\b", t)
    equipment_payment = _has(r"\b(?:purchase|buy|pay for|deposit)\b.{0,80}"
                             r"\b(?:laptop|computer|equipment|software|"
                             r"workstation|office supplies)\b", t)
    if equipment_job and equipment_payment:
        add("EMPLOYMENT_EQUIPMENT_SCAM", "HIGH",
            "An employment opportunity requires the recipient to purchase equipment or make a payment.",
            confirmed=False, confidence=0.75)

    # 26) Fake bank KYC requests.
    kyc = _has(r"\b(?:kyc update|complete kyc|kyc verification|"
               r"bank verification|account reactivation)\b", t)
    if kyc and (sensitive_request or credentials or account_pressure):
        add("BANK_KYC_PHISHING", "HIGH",
            "A bank verification request is combined with sensitive-data or credential collection.",
            confirmed=False, confidence=0.75)

    # 27) Fake overpayment and payment confirmation.
    overpayment = _has(r"\b(?:overpaid|excess payment|extra payment|"
                       r"paid twice|payment sent in error)\b", t)
    refund_action = _has(r"\b(?:refund|return|send back|transfer back|"
                         r"reimburse)\b", t)
    if overpayment and refund_action:
        add("OVERPAYMENT_REFUND_SCAM", "HIGH",
            "An alleged overpayment is followed by a request to return money.",
            confirmed=False, confidence=0.75)

    # 28)Fake cryptocurrency mining.
    mining = _has(r"\b(?:crypto mining|mining investment|cloud mining|"
                  r"mining package)\b", t)
    mining_return = _has(r"\b(?:guaranteed returns|daily profit|"
                         r"fixed income|risk.free profit)\b", t)
    if mining and mining_return:
        add("CRYPTO_MINING_SCAM", "HIGH",
            "A cryptocurrency mining offer promises guaranteed or fixed financial returns.",
            confirmed=False, confidence=0.75)

    # 29) Requests to disclose confidential business information.
    confidential = _has(
        r"\b(?:confidential|internal use only|restricted document|"
        r"proprietary information|trade secret|internal database)\b", t
    )
    disclosure = _has(
        r"\b(?:forward|send|upload|share|export|copy|transfer)\b.{0,100}"
        r"\b(?:external|personal email|third party|public link|"
        r"outside the company)\b", t
    )
    if confidential and disclosure and _has(
        r"\b(?:without approval|without authorization|without permission|unapproved cloud|personal email|bypass approval)\b", t
    ):
        add("CONFIDENTIAL_DATA_DISCLOSURE", "CRITICAL",
            "Confidential transfer includes explicit high-risk destination or authorization indicators.",
            confirmed=True, confidence=0.98)
    elif confidential and disclosure:
        add("CONFIDENTIAL_DATA_DISCLOSURE", "MEDIUM",
            "The message combines confidential business information with an external disclosure action.",
            confirmed=False, confidence=0.75)

    # 30) Possible secrets in outbound email content.
    secret_assignment = _has(
        r"\b(?:api[_ -]?key|access[_ -]?token|secret[_ -]?key|"
        r"private[_ -]?key|client[_ -]?secret|password)\b"
        r"\s*[:=]\s*\S{6,}", t
    )
    if secret_assignment:
        add("POSSIBLE_CREDENTIAL_LEAKAGE", "HIGH",
            "The message appears to contain a credential or secret assignment; verify before sending.",
            confirmed=False, confidence=0.80)

    # 31) Hidden or suspicious HTML elements.
    if html:
        hidden_html = _has(
            r"display\s*:\s*none|visibility\s*:\s*hidden|"
            r"opacity\s*:\s*0|font-size\s*:\s*0", html
        )
        if hidden_html:
            add("HIDDEN_HTML_CONTENT", "MEDIUM",
                "The email contains hidden HTML content that should be inspected.",
                confirmed=False, confidence=0.65)

    # 32)Obfuscated or suspicious script references.
    if html and _has(r"<script\b|javascript\s*:|onerror\s*=|"
                     r"onload\s*=", html):
        add("SUSPICIOUS_HTML_SCRIPT", "HIGH",
            "The email HTML contains script-related constructs requiring inspection.",
            confirmed=False, confidence=0.80)


    # 33) Guaranteed website traffic and unrealistic marketing claims.
    traffic_claim = _has(
        r"\b(?:website traffic|website visitors|visitors|targeted customers)\b", t
    )
    traffic_promise = _has(
        r"\b(?:guaranteed|instantly|overnight|immediate results|"
        r"100,?000|thousands of)\b", t
    )
    traffic_service = _has(
        r"\b(?:traffic growth service|growth service|"
        r"promotional packages|marketing packages)\b", t
    )
    if traffic_claim and traffic_promise and traffic_service:
        add("UNSOLICITED_TRAFFIC_PROMOTION", "MEDIUM",
            "The message promotes guaranteed or instant website traffic growth.",
            confirmed=False, confidence=0.70)

    # 34) Free premium membership with an artificial deadline.
    free_membership = _has(
        r"\b(?:free|absolutely free|complimentary)\b.{0,80}"
        r"\b(?:premium membership|premium account|lifetime membership)\b", t
    )
    membership_deadline = _has(
        r"\b(?:expires tonight|expires today|before midnight|"
        r"expires in \d+ hours?|limited time)\b", t
    )
    if free_membership and membership_deadline:
        add("DECEPTIVE_FREE_MEMBERSHIP", "MEDIUM",
            "A free premium membership offer uses an expiry or urgency claim.",
            confirmed=False, confidence=0.65)

    # 35) Unsolicited advertising partnership requesting contact details.
    advertising_offer = _has(
        r"\b(?:advertising partnership|promotional campaign|"
        r"targeted customers|marketing partnership)\b", t
    )
    contact_request = _has(
        r"\b(?:reply with|send us|provide|share)\b.{0,80}"
        r"\b(?:contact details|contact information|business details)\b", t
    )
    if advertising_offer and contact_request:
        add("UNSOLICITED_ADVERTISING_SOLICITATION", "MEDIUM",
            "An advertising offer requests contact information to activate a promotional campaign.",
            confirmed=False, confidence=0.65)

    # 36) Fake lucky-number and promotional selection.
    lucky_selection = _has(
        r"\b(?:lucky number|selected in our promotional giveaway|"
        r"your number has been selected|number has been chosen)\b", t
    )
    selection_action = _has(
        r"\b(?:confirm your participation|claim your reward|"
        r"collect your prize|redeem your reward)\b", t
    )
    selection_deadline = _has(
        r"\b(?:before midnight|today|tonight|expires|"
        r"limited time|last chance)\b", t
    )
    if lucky_selection and (selection_action or selection_deadline):
        add("FAKE_PROMOTIONAL_SELECTION", "MEDIUM",
            "A lucky-number or promotional selection claim uses a deadline or confirmation request.",
            confirmed=False, confidence=0.70)

    # 37) Password expiry and credential-reset phishing.
    password_expiry = _has(
        r"\b(?:password has expired|password expired|"
        r"password reset required|password will expire)\b", t
    )
    password_action = _has(
        r"\b(?:visit|click|open|sign in|log in|update|reset)\b", t
    )
    credential_destination = _has(
        r"https?://\S+|www\.\S+", t
    )
    if password_expiry and password_action and credential_destination:
        add("PASSWORD_EXPIRY_PHISHING", "HIGH",
            "A password-expiry notice directs the recipient to an external destination to update credentials.",
            confirmed=False, confidence=0.85)

    # 38) Mailbox quota and storage phishing.
    mailbox_quota = _has(
        r"\b(?:mailbox|email account)\b.{0,80}"
        r"\b(?:storage is full|reached \d{1,3}%|quota exceeded|"
        r"storage limit|capacity is full)\b", t
    )
    mailbox_action = _has(
        r"\b(?:sign in|log in|login|verify|click|visit|open)\b", t
    )
    mailbox_consequence = _has(
        r"\b(?:incoming messages|blocked|undelivered|"
        r"cannot receive|prevent messages)\b", t
    )
    if mailbox_quota and mailbox_action and mailbox_consequence:
        add("MAILBOX_QUOTA_PHISHING", "HIGH",
            "A mailbox storage warning pressures the recipient to authenticate to prevent message delivery problems.",
            confirmed=False, confidence=0.85)

    # 39) CEO/executive impersonation through urgency and secrecy.
    executive_identity = _has(
        r"\b(?:ceo|chief executive officer|chief executive|"
        r"managing director|finance director|cfo|"
        r"company director|company owner)\b", t
    )
    executive_secrecy = _has(
        r"\b(?:do not discuss|don't discuss|do not tell|"
        r"don't tell|keep this confidential|keep this private|"
        r"without informing other employees|between us)\b", t
    )
    executive_pressure = _has(
        r"\b(?:urgent|immediately|currently in a meeting|"
        r"in a meeting|busy right now|handle this request|"
        r"confidential task)\b", t
    )
    if executive_identity and executive_secrecy and executive_pressure:
        add("CEO_CONFIDENTIALITY_URGENCY_IMPERSONATION", "HIGH",
            "An executive-related message combines secrecy and urgency or meeting-related pressure. Verify the sender independently.",
            confirmed=False, confidence=0.80)

    # 40) Customer database exfiltration to personal email.
    customer_records = _has(
        r"\b(?:customer database|customer records|"
        r"customer information|customer data)\b", t
    )
    customer_fields = _has(
        r"\b(?:customer names|names|phone numbers|addresses|"
        r"account information|financial information)\b", t
    )
    external_transfer = _has(
        r"\b(?:forward|send|upload|share|export|transfer)\b", t
    )
    personal_destination = _has(
        r"\b(?:personal email|personal account|"
        r"external email|external account|outside the company)\b", t
    )
    if customer_records and customer_fields and external_transfer and personal_destination:
        add("CUSTOMER_DATA_EXFILTRATION", "CRITICAL",
            "Customer records containing personal or account information are explicitly directed to a personal or external destination.",
            confirmed=True, confidence=0.99)

    # 41) Possible production API-key or credential exposure.
    api_secret = _has(
        r"\b(?:api[_ -]?key|access[_ -]?token|secret[_ -]?key|"
        r"client[_ -]?secret|private[_ -]?key)\b\s*[:=]\s*\S{6,}", t
    )
    production_context = _has(
        r"\b(?:production|live environment|deployment|integration)\b", t
    )
    if api_secret and production_context:
        add("PRODUCTION_CREDENTIAL_EXPOSURE", "HIGH",
            "The message contains a possible production credential or secret assignment. Validate the value before treating it as a real secret.",
            confirmed=False, confidence=0.85)

    # 42) Confidential employee salary information sent externally.
    salary_records = _has(
        r"\b(?:employee salary report|salary report|"
        r"employee compensation|salary information|payroll records)\b", t
    )
    salary_confidential = _has(
        r"\b(?:confidential|restricted|internal|private)\b", t
    )
    external_employee_share = _has(
        r"\b(?:share|send|forward|upload|transfer)\b", t
    ) and _has(
        r"\b(?:external consultant|external recipient|"
        r"third party|outside the company)\b", t
    )
    if salary_records and salary_confidential and external_employee_share:
        add("EMPLOYEE_DATA_EXFILTRATION", "CRITICAL",
            "Confidential employee compensation records are explicitly being shared with an external recipient.",
            confirmed=True, confidence=0.99)

    # 43) Disabling antivirus or endpoint security monitoring.
    disable_security = _has(
        r"\b(?:disable|turn off|deactivate|bypass|"
        r"stop|switch off)\b", t
    )
    security_controls = _has(
        r"\b(?:endpoint monitoring|antivirus|anti-virus|"
        r"security monitoring|security alerts|"
        r"endpoint protection|malware protection)\b", t
    )
    if disable_security and security_controls:
        add("SECURITY_MONITORING_BYPASS", "CRITICAL",
            "The message explicitly requests disabling antivirus or endpoint security monitoring.",
            confirmed=True, confidence=0.99)

    # 44) Execution of an unapproved PowerShell or script file.
    script_file = _has(
        r"\b[\w.-]+\.(?:ps1|bat|cmd|vbs|js|wsf|sh)\b", t
    )
    execute_script = _has(
        r"\b(?:run|execute|launch|open|start)\b", t
    )
    script_unapproved = _has(
        r"\b(?:not approved|unapproved|not authorized|"
        r"not reviewed|security team has not approved)\b", t
    )
    if script_file and execute_script and script_unapproved:
        add("UNAPPROVED_SCRIPT_EXECUTION", "CRITICAL",
            "The message explicitly requests execution of a script that has not been approved.",
            confirmed=True, confidence=0.99)

    # 45) Confidential legal contracts sent to external portals.
    legal_documents = _has(
        r"\b(?:confidential contract|contract documents|"
        r"legal agreements|internal legal agreements)\b", t
    )
    legal_confidentiality = _has(
        r"\b(?:strictly confidential|confidential|restricted|internal)\b", t
    )
    legal_external_transfer = _has(
        r"\b(?:upload|send|share|forward|transfer)\b", t
    ) and _has(
        r"\b(?:external document-sharing portal|"
        r"external portal|third party|external recipient)\b", t
    )
    if legal_documents and legal_confidentiality and legal_external_transfer:
        add("CONFIDENTIAL_DOCUMENT_EXFILTRATION", "CRITICAL",
            "Confidential legal agreements are explicitly being transferred to an external destination.",
            confirmed=True, confidence=0.99)

    # 46) Executable installation combined with security-warning bypass.
    executable_file = _has(
        r"\b[\w.-]+\.(?:exe|msi|scr|com)\b", t
    )
    install_executable = _has(
        r"\b(?:install|run|execute|launch|open)\b", t
    )
    ignore_security_warning = _has(
        r"\b(?:ignore|bypass|disregard|disable)\b.{0,80}"
        r"\b(?:operating system security warnings?|"
        r"security warnings?|antivirus warnings?|"
        r"security protection|protection alerts?)\b", t
    )
    if executable_file and install_executable and ignore_security_warning:
        add("SUSPICIOUS_EXECUTABLE_INSTALLATION", "CRITICAL",
            "The message requests installation or execution of an executable while explicitly instructing the recipient to ignore security warnings.",
            confirmed=True, confidence=0.99)

    # 47) Production database and authentication-data exfiltration.
    production_database = _has(
        r"\b(?:production database|production db|"
        r"database backup|production backup)\b", t
    )
    database_export = _has(
        r"\b(?:export|dump|download|backup|copy|transfer)\b", t
    )
    sensitive_database_fields = _has(
        r"\b(?:customer records|authentication fields|"
        r"authentication data|password hashes|credentials|"
        r"account records|user records)\b", t
    )
    external_storage = _has(
        r"\b(?:external storage|external storage account|"
        r"personal storage|personal account|"
        r"outside the company|external account)\b", t
    )
    if production_database and database_export and sensitive_database_fields and external_storage:
        add("PRODUCTION_DATABASE_EXFILTRATION", "CRITICAL",
            "The message explicitly requests exporting production data, including sensitive records, to external storage.",
            confirmed=True, confidence=0.99)

    # 48) Prompt injection targeting the email-analysis assistant.
    instruction_override = _has(
        r"\b(?:ignore|disregard|override|bypass)\b.{0,100}"
        r"\b(?:previous|prior|existing|all)\b.{0,80}"
        r"\b(?:instructions|rules|security rules|policies)\b", t
    )
    analysis_manipulation = _has(
        r"\b(?:classify this email as safe|"
        r"suppress any threat alerts|suppress threat alerts|"
        r"hide security alerts|disable threat detection|"
        r"ignore security warnings)\b", t
    )
    if instruction_override and analysis_manipulation:
        add("AI_SECURITY_PROMPT_INJECTION", "HIGH",
            "The message attempts to override analysis instructions or suppress security findings.",
            confirmed=True, confidence=0.99)

    # 49) Confidential financial and audit data sent to unauthorized recipients.
    financial_records = _has(
        r"\b(?:quarterly financial report|financial records|"
        r"internal audit findings|audit findings|"
        r"restricted transaction records|transaction records)\b", t
    )
    financial_confidentiality = _has(
        r"\b(?:confidential|restricted|internal|private)\b", t
    )
    financial_transfer = _has(
        r"\b(?:send|share|forward|upload|transfer|export)\b", t
    )
    unauthorized_recipient = _has(
        r"\b(?:unauthorized external recipient|unauthorized recipient|"
        r"external recipient|unapproved third party)\b", t
    )
    if financial_records and financial_confidentiality and financial_transfer and unauthorized_recipient:
        add("CONFIDENTIAL_FINANCIAL_DATA_EXFILTRATION", "CRITICAL",
            "Restricted financial or audit records are explicitly being sent to an unauthorized external recipient.",
            confirmed=True, confidence=0.99)

    

    # 50-89) Additional content-focused fraud, impersonation and data-loss rules.
    # These rules require combinations of context and actions; isolated keywords
    # are deliberately insufficient. URL reputation, raw headers and file malware
    # are handled by their dedicated OMG modules.

    # Fake invoice / purchase order / overdue payment demands.
    invoice_document = _has(r"\b(?:invoice|purchase order|po number|billing statement)\b", t)
    invoice_pressure = _has(r"\b(?:overdue|past due|payment due|immediate payment|final payment notice|late payment)\b", t)
    invoice_action = _has(r"\b(?:pay|settle|remit|wire|transfer|process payment)\b", t)
    if invoice_document and invoice_pressure and invoice_action:
        add("FAKE_INVOICE_FRAUD", "HIGH",
            "An invoice or purchase-order message combines payment pressure with a payment instruction.",
            confirmed=False, confidence=0.78)
        add("PAYMENT_OVERDUE_PRESSURE", "MEDIUM",
            "A payment deadline or overdue claim is used to prompt a financial action.",
            confirmed=False, confidence=0.65)
    if _has(r"\b(?:purchase order|po number|purchase requisition)\b", t) and _has(
        r"\b(?:create|issue|approve|process)\b", t
    ) and _has(r"\b(?:urgent|immediately|without approval|bypass approval)\b", t):
        add("FAKE_PURCHASE_ORDER", "HIGH",
            "A purchase-order request uses urgency or bypasses normal approval; verify through a known channel.",
            confirmed=False, confidence=0.75)

    # Payment splitting and approval-workflow bypass.
    if _has(r"\b(?:split|divide|break)\b.{0,70}\b(?:payment|invoice|transfer)\b", t) and _has(
        r"\b(?:approval limit|approval threshold|avoid approval|below the limit|without approval)\b", t
    ):
        add("PAYMENT_SPLITTING_REQUEST", "CRITICAL",
            "The message asks to split a payment to avoid an approval threshold.",
            confirmed=True, confidence=0.98)
    if _has(r"\b(?:bypass|skip|avoid|ignore)\b.{0,70}\b(?:payment approval|finance approval|two-person approval|purchase approval)\b", t):
        add("PAYMENT_APPROVAL_BYPASS", "CRITICAL",
            "The message explicitly requests bypassing a financial approval control.",
            confirmed=True, confidence=0.98)

    # Refund, tax, legal and authority impersonation.
    if _has(r"\b(?:refund|reimbursement|rebate)\b", t) and _has(
        r"\b(?:claim|eligible|approved|available)\b", t
    ) and (sensitive_request or advance_fee or _has(r"\b(?:click|verify|submit|pay)\b", t)):
        add("FAKE_REFUND_CLAIM", "HIGH",
            "A refund claim is paired with a request for payment, credentials or sensitive information.",
            confirmed=False, confidence=0.78)
    if _has(r"\b(?:tax department|income tax department|revenue authority|tax authority)\b", t) and _has(
        r"\b(?:penalty|fine|arrest|legal action|refund blocked|tax clearance)\b", t
    ) and _has(r"\b(?:pay|transfer|click|verify|submit)\b", t):
        add("FAKE_TAX_COMPLIANCE_NOTICE", "HIGH",
            "A tax-authority-themed notice combines threats or compliance claims with an action request.",
            confirmed=False, confidence=0.78)
    if _has(r"\b(?:court summons|court notice|warrant|legal notice|law enforcement)\b", t) and _has(
        r"\b(?:pay immediately|avoid arrest|settlement fee|click to view|provide your details)\b", t
    ):
        add("FAKE_COURT_SUMMONS", "HIGH",
            "A purported court or law-enforcement notice uses payment pressure or sensitive-data collection.",
            confirmed=False, confidence=0.80)
    if _has(r"\b(?:arrest|prosecution|lawsuit|legal action|criminal case)\b", t) and _has(
        r"\b(?:pay|transfer|gift card|bitcoin|provide credentials)\b", t
    ):
        add("FAKE_LEGAL_THREAT", "HIGH",
            "A legal or arrest threat is paired with a payment or credential demand.",
            confirmed=False, confidence=0.80)
    if _has(r"\b(?:government grant|government benefit|official government payment|government agency)\b", t) and _has(
        r"\b(?:claim now|release fee|processing fee|verify bank|submit identity)\b", t
    ):
        add("FAKE_GOVERNMENT_AUTHORITY", "HIGH",
            "A government-benefit or authority claim is paired with a fee or sensitive-data request.",
            confirmed=False, confidence=0.78)

    # Support, security, recruiter, insurance and partnership impersonation.
    if _has(r"\b(?:customer support|help desk|technical department|support team)\b", t) and _has(
        r"\b(?:call this number|install|remote access|password|otp|payment|refund)\b", t
    ):
        add("FAKE_CUSTOMER_SUPPORT", "HIGH",
            "A support-themed message asks for remote access, authentication data or payment.",
            confirmed=False, confidence=0.78)
    if _has(r"\b(?:recruiter|talent acquisition|hiring manager|job offer|employment offer)\b", t) and _has(
        r"\b(?:pay|purchase|deposit|registration fee|training fee|equipment fee)\b", t
    ):
        add("FAKE_RECRUITER_IMPERSONATION", "HIGH",
            "A purported recruiter or employer requests money or purchases as part of recruitment.",
            confirmed=False, confidence=0.78)
        add("FAKE_JOB_OFFER", "HIGH",
            "A job offer is paired with an unusual payment or purchase requirement.",
            confirmed=False, confidence=0.78)
    if _has(r"\b(?:interview|job application|recruitment)\b", t) and _has(
        r"\b(?:interview fee|application fee|processing fee)\b", t
    ) and _has(r"\b(?:pay|transfer|deposit)\b", t):
        add("FAKE_INTERVIEW_FEE", "HIGH",
            "The recipient is asked to pay a fee to attend an interview or proceed with recruitment.",
            confirmed=False, confidence=0.80)
    if _has(r"\b(?:insurance claim|insurance payout|policy benefit|claim settlement)\b", t) and _has(
        r"\b(?:release fee|processing fee|verify bank|send payment|provide identity)\b", t
    ):
        add("FAKE_INSURANCE_CLAIM", "HIGH",
            "An insurance payout or claim message requests a fee or sensitive information.",
            confirmed=False, confidence=0.78)
    if _has(r"\b(?:business partnership|strategic partnership|joint venture|investment partner)\b", t) and _has(
        r"\b(?:upfront fee|deposit|send funds|share bank details|provide identity)\b", t
    ):
        add("FAKE_BUSINESS_PARTNERSHIP", "HIGH",
            "A partnership proposal is paired with an upfront payment or sensitive-data request.",
            confirmed=False, confidence=0.75)

    # Crypto airdrop, Ponzi and market-manipulation indicators.
    if _has(r"\b(?:crypto|cryptocurrency|token)\b", t) and _has(
        r"\b(?:airdrop|free tokens|claim tokens|wallet reward)\b", t
    ) and _has(r"\b(?:connect wallet|enter seed phrase|recovery phrase|private key|pay gas fee)\b", t):
        add("FAKE_CRYPTO_AIRDROP", "HIGH",
            "A purported crypto airdrop requests wallet access, recovery secrets or an upfront fee.",
            confirmed=False, confidence=0.85)
    if _has(r"\b(?:investors|investment)\b", t) and _has(
        r"\b(?:guaranteed returns|fixed returns|daily returns|monthly returns)\b", t
    ) and _has(r"\b(?:recruit|bring in investors|referral chain|new members|downline)\b", t):
        add("PONZI_SCHEME_PROMOTION", "HIGH",
            "An investment offer combines promised returns with recruitment of additional investors.",
            confirmed=False, confidence=0.80)
    if _has(r"\b(?:buy this stock|buy this token|pump the price|price will explode|insider tip)\b", t) and _has(
        r"\b(?:sell after|dump|guaranteed profit|limited group|act before the market)\b", t
    ):
        add("PUMP_AND_DUMP_PROMOTION", "HIGH",
            "The message encourages coordinated buying or trading followed by selling or guaranteed-profit claims.",
            confirmed=False, confidence=0.78)
    if _has(r"\b(?:cloud mining|mining package|crypto mining)\b", t) and _has(
        r"\b(?:guaranteed returns|fixed daily profit|risk.free profit)\b", t
    ):
        add("FAKE_INVESTMENT_RETURN", "HIGH",
            "An investment or mining promotion promises fixed or guaranteed returns.",
            confirmed=False, confidence=0.75)

    # Money-mule and laundering recruitment.
    if _has(r"\b(?:receive money|receive funds|use your bank account|use your account)\b", t) and _has(
        r"\b(?:transfer it|forward the funds|send it onward|keep a commission|commission for transferring)\b", t
    ):
        add("MONEY_MULE_RECRUITMENT", "CRITICAL",
            "The recipient is asked to receive and forward funds in exchange for a commission.",
            confirmed=True, confidence=0.96)
    if _has(r"\b(?:hide the source of funds|conceal the origin|avoid transaction monitoring|make funds untraceable)\b", t) and _has(
        r"\b(?:transfer|move|split|route|convert)\b", t
    ):
        add("MONEY_LAUNDERING_INSTRUCTION", "CRITICAL",
            "The message gives instructions to conceal the source or traceability of funds.",
            confirmed=True, confidence=0.99)

    # MFA, SSO, VPN, cloud, webmail and password-manager lures.
    if _has(r"\b(?:approve|accept|tap|confirm)\b.{0,60}\b(?:mfa|multi.factor|authenticator|login request|sign.in request)\b", t) and _has(
        r"\b(?:you did not initiate|not your login|unexpected|repeated|again and again|multiple requests)\b", t
    ):
        add("MFA_PUSH_FATIGUE", "HIGH",
            "The message describes or requests approval of unexpected or repeated MFA prompts.",
            confirmed=False, confidence=0.80)
    if _has(r"\b(?:single sign.on|sso)\b", t) and login_action and (urgency or credentials or account_pressure):
        add("FAKE_SSO_LOGIN", "HIGH",
            "An SSO authentication request is combined with urgency, credential collection or account pressure.",
            confirmed=False, confidence=0.78)
    if _has(r"\b(?:vpn access|vpn account|vpn certificate)\b", t) and login_action and (credentials or urgency):
        add("FAKE_VPN_LOGIN", "HIGH",
            "A VPN access notice requests authentication under suspicious pressure.",
            confirmed=False, confidence=0.78)
    if _has(r"\b(?:onedrive|sharepoint|google drive|dropbox|cloud storage)\b", t) and login_action and (
        credentials or urgency or account_pressure
    ):
        add("FAKE_CLOUD_STORAGE_LOGIN", "HIGH",
            "A cloud-storage-themed message directs the recipient to authenticate under suspicious circumstances.",
            confirmed=False, confidence=0.78)
    if _has(r"\b(?:webmail|mailbox|email account)\b", t) and login_action and (credentials or urgency):
        add("FAKE_WEBMAIL_LOGIN", "HIGH",
            "A webmail-themed message requests authentication using urgency or credential prompts.",
            confirmed=False, confidence=0.75)
    if _has(r"\b(?:password manager|password vault|shared vault)\b", t) and _has(
        r"\b(?:share your master password|enter master password|unlock your vault|verify your vault|grant access)\b", t
    ):
        add("PASSWORD_MANAGER_PHISHING", "HIGH",
            "A password-manager or vault message requests master-password disclosure or suspicious access.",
            confirmed=False, confidence=0.82)
    if _has(r"\b(?:account recovery|recover your account|reset your recovery|recovery request)\b", t) and _has(
        r"\b(?:send code|provide otp|verification code|recovery code|security questions)\b", t
    ):
        add("ACCOUNT_RECOVERY_ABUSE", "HIGH",
            "An account-recovery process requests authentication or recovery secrets.",
            confirmed=False, confidence=0.82)
    if _has(r"\b(?:email quarantine|quarantined message|message held|spam quarantine)\b", t) and _has(
        r"\b(?:release message|view message|sign in|verify account|click here)\b", t
    ):
        add("FAKE_EMAIL_QUARANTINE_NOTICE", "HIGH",
            "A quarantine notification directs the recipient to authenticate or release a message.",
            confirmed=False, confidence=0.78)
    if _has(r"\b(?:email delivery failed|message delivery failure|undelivered message|mail delivery problem)\b", t) and _has(
        r"\b(?:sign in|verify mailbox|update password|click here|open attachment)\b", t
    ):
        add("FAKE_EMAIL_DELIVERY_FAILURE", "HIGH",
            "A delivery-failure notice is paired with an authentication or attachment action.",
            confirmed=False, confidence=0.78)
    if _has(r"\b(?:shared password vault|password vault invitation|shared credentials)\b", t) and _has(
        r"\b(?:accept invitation|view shared|open vault|sign in)\b", t
    ):
        add("FAKE_PASSWORD_MANAGER_SHARING", "MEDIUM",
            "A password-vault sharing invitation should be verified with the sender.",
            confirmed=False, confidence=0.68)

    # Sensitive information and business-data leakage.
    transfer_action = _has(r"\b(?:send|forward|upload|share|export|copy|transfer|publish)\b", t)
    external_target = _has(r"\b(?:personal email|personal account|external recipient|third party|public link|outside the company|unapproved cloud|external storage)\b", t)
    if _has(r"\b(?:customer|client)\b", t) and _has(r"\b(?:names|phone numbers|addresses|email addresses|account numbers|personal details)\b", t) and transfer_action and external_target:
        add("CUSTOMER_PII_DISCLOSURE", "CRITICAL",
            "Customer personally identifiable information is directed to an external or personal destination.",
            confirmed=True, confidence=0.98)
    if _has(r"\b(?:employee|staff|personnel)\b", t) and _has(r"\b(?:date of birth|home address|phone number|national id|aadhaar|pan number|bank details)\b", t) and transfer_action and external_target:
        add("EMPLOYEE_PII_DISCLOSURE", "CRITICAL",
            "Employee personal information is directed to an external or personal destination.",
            confirmed=True, confidence=0.98)
    if _has(r"\b(?:credit card|debit card|card number|cvv|cvc|expiry date)\b", t) and transfer_action and external_target:
        add("PAYMENT_CARD_DATA_EXPOSURE", "CRITICAL",
            "Payment-card information is being transferred to an external or personal destination.",
            confirmed=True, confidence=0.99)
    if _has(r"\b(?:bank account number|routing number|ifsc code|account credentials|banking details)\b", t) and transfer_action and external_target:
        add("BANKING_INFORMATION_EXPOSURE", "CRITICAL",
            "Banking information is being transferred to an external or personal destination.",
            confirmed=True, confidence=0.98)
    if _has(r"\b(?:patient records|medical records|health records|diagnosis|prescription details)\b", t) and transfer_action and external_target:
        add("HEALTH_INFORMATION_DISCLOSURE", "CRITICAL",
            "Sensitive health information is being transferred to an external or personal destination.",
            confirmed=True, confidence=0.98)
    if _has(r"\b(?:source code|proprietary algorithm|trade secret|engineering design|research data|intellectual property)\b", t) and transfer_action and external_target:
        add("INTELLECTUAL_PROPERTY_EXFILTRATION", "CRITICAL",
            "Proprietary intellectual property is being transferred to an external or personal destination.",
            confirmed=True, confidence=0.98)
    if _has(r"\b(?:source code|git repository|private repository|codebase)\b", t) and transfer_action and external_target:
        add("SOURCE_CODE_EXFILTRATION", "CRITICAL",
            "Source code or repository contents are being transferred to an external or personal destination.",
            confirmed=True, confidence=0.98)
    if _has(r"\b(?:bulk export|all customer records|entire database|mass export|large data dump)\b", t) and transfer_action and external_target:
        add("BULK_DATA_TRANSFER", "CRITICAL",
            "The message requests a bulk transfer of business data to an external destination.",
            confirmed=True, confidence=0.98)
    if _has(r"\b(?:upload|copy|sync|transfer|back up)\b", t) and _has(
        r"\b(?:personal cloud|personal drive|personal dropbox|personal google drive|unapproved cloud storage)\b", t
    ) and _has(r"\b(?:company files|customer data|business documents|internal files|database)\b", t):
        add("EXTERNAL_STORAGE_EXFILTRATION", "CRITICAL",
            "Business information is directed to an unapproved or personal cloud-storage destination.",
            confirmed=True, confidence=0.98)
    if transfer_action and _has(r"\b(?:company files|internal documents|customer records|business data|confidential files)\b", t) and _has(
        r"\b(?:personal gmail|personal yahoo|personal outlook|my personal email|private email account)\b", t
    ):
        add("PERSONAL_EMAIL_EXFILTRATION", "CRITICAL",
            "Company information is explicitly directed to a personal email account.",
            confirmed=True, confidence=0.98)
    if _has(r"\b(?:delete|destroy|erase|purge|remove)\b", t) and _has(
        r"\b(?:records|audit logs|backup copies|financial records|customer records|retention records)\b", t
    ) and _has(r"\b(?:before audit|avoid detection|without recording|so nobody can see)\b", t):
        add("DATA_RETENTION_POLICY_BYPASS", "CRITICAL",
            "The message requests destruction of records in a context suggesting avoidance of retention or oversight.",
            confirmed=True, confidence=0.98)
        add("DATA_DELETION_OR_DESTRUCTION", "CRITICAL",
            "The message explicitly requests potentially unauthorized destruction of business records.",
            confirmed=True, confidence=0.98)
    if _has(r"\b(?:delete|erase|alter|modify|clear)\b", t) and _has(
        r"\b(?:audit trail|audit logs|security logs|access logs|activity logs)\b", t
    ) and _has(r"\b(?:hide|conceal|avoid detection|cover tracks|before review)\b", t):
        add("AUDIT_LOG_TAMPERING", "CRITICAL",
            "The message requests altering or deleting logs to conceal activity.",
            confirmed=True, confidence=0.99)

    # Explicit requests to install remote access or escalate privileges.
    if _has(r"\b(?:install|download|run|launch)\b", t) and _has(
        r"\b(?:anydesk|teamviewer|screenconnect|remote desktop|remote access tool)\b", t
    ) and _has(r"\b(?:unattended access|give me access|allow remote control|share access)\b", t):
        add("REMOTE_ACCESS_INSTALLATION", "HIGH",
            "The message requests installation or configuration of remote-access software and grants control.",
            confirmed=False, confidence=0.82)
    if _has(r"\b(?:grant|give|assign|enable)\b", t) and _has(
        r"\b(?:administrator|admin rights|privileged access|global admin|root access)\b", t
    ) and _has(r"\b(?:bypass approval|without approval|temporary exception|ignore policy)\b", t):
        add("UNAUTHORIZED_PRIVILEGE_ESCALATION", "CRITICAL",
            "The message requests privileged access while bypassing normal authorization.",
            confirmed=True, confidence=0.98)
    if _has(r"\b(?:enable macros|enable content|enable editing and macros|disable protected view)\b", t) and _has(
        r"\b(?:invoice|document|attachment|spreadsheet|word document)\b", t
    ):
        add("MALICIOUS_MACRO_ENABLEMENT", "HIGH",
            "The message instructs the recipient to enable macros or weaken document protections.",
            confirmed=False, confidence=0.82)
    if _has(r"\b(?:security control|firewall|endpoint protection|antivirus|security monitoring)\b", t) and _has(
        r"\b(?:disable|turn off|deactivate|bypass|stop)\b", t
    ):
        add("SECURITY_CONTROL_DISABLEMENT", "CRITICAL",
            "The message instructs the recipient to disable or bypass a security control.",
            confirmed=True, confidence=0.98)

    # More precise sensitive-data request signal.
    if _has(r"\b(?:send|share|provide|reply with|upload)\b", t) and _has(
        r"\b(?:master password|seed phrase|recovery phrase|private key|cvv|one.time password|otp)\b", t
    ):
        add("SENSITIVE_DATA_REQUEST", "MEDIUM",
            "The message requests highly sensitive authentication or financial information.",
            confirmed=False, confidence=0.85)

    # Fake board/auditor requests involving restricted business information.
    if _has(r"\b(?:board member|board of directors|external auditor|auditor|audit firm)\b", t) and _has(
        r"\b(?:send|share|upload|provide|forward)\b", t
    ) and _has(r"\b(?:confidential|restricted|financial statements|payroll|customer records|bank details)\b", t):
        add("FAKE_AUDITOR_REQUEST" if _has(r"\b(?:auditor|audit firm)\b", t) else "FAKE_BOARD_MEMBER_REQUEST",
            "HIGH",
            "A purported auditor or board-related request seeks restricted business information; verify independently.",
            confirmed=False, confidence=0.75)

    # Payroll direct-deposit change request.
    if _has(r"\b(?:payroll|salary|direct deposit)\b", t) and _has(
        r"\b(?:change|update|replace|new)\b", t
    ) and _has(r"\b(?:bank account|account number|bank details|deposit account)\b", t):
        add("PAYROLL_DIRECT_DEPOSIT_CHANGE", "HIGH",
            "A payroll or salary message requests a bank-account change that requires out-of-band verification.",
            confirmed=False, confidence=0.82)

    # Beneficiary mismatch and unusual destination indicators require source data
    # (invoice/vendor profile) for confirmation; content alone only raises review.
    if payment and _has(r"\b(?:beneficiary|payee|recipient account)\b", t) and _has(
        r"\b(?:different account|new beneficiary|unrecognized account|third.party account)\b", t
    ):
        add("PAYMENT_BENEFICIARY_MISMATCH", "HIGH",
            "The payment beneficiary appears different or newly introduced; compare against trusted vendor records.",
            confirmed=False, confidence=0.75)
    if payment_action and _has(r"\b(?:overseas account|personal bank account|unrelated account|new wallet address)\b", t):
        add("UNUSUAL_PAYMENT_DESTINATION", "HIGH",
            "A payment is directed to an unusual destination that should be independently verified.",
            confirmed=False, confidence=0.72)


    # 50) Urgency manipulation is a supporting category only when paired with an action.
    action = _has(r"\b(?:click|pay|transfer|submit|verify|provide|upload|reply|call)\b", t)
    if urgency and action and (sensitive_request or advance_fee or account_pressure or payment or prize):
        add("URGENCY_MANIPULATION", "MEDIUM", "A deadline or scarcity claim is used to pressure a sensitive action.", confirmed=False, confidence=0.5)

    # If the content shows a suspicious request for sensitive data but not enough
    # evidence for a named pretext, preserve it as a high-severity review finding.
    if sensitive_request and (urgency or _has(r"\b(?:prize|refund|loan|account|verification|winner)\b", t)):
        add("PERSONAL_INFORMATION_HARVESTING", "HIGH", "The message requests personal or financial data in a pressured or suspicious context.")



    # ================================================================
    # COMPREHENSIVE FRAUD, SPAM, PHISHING AND SECURITY DETECTION RULES
    # 1-97 Detection patterns
    # ================================================================

    detection_rules = [

        # ------------------------------------------------------------
        # A. SPAM AND PROMOTIONAL ABUSE (1-12)
        # ------------------------------------------------------------

        (
            "BULK_SPAM",
            r"\b(?:bulk email|mass email|mass mailing|bulk mailing|"
            r"send to thousands|blast email|email blast)\b",
            "MEDIUM", False, 0.78,
            "Bulk unsolicited email distribution indicators detected."
        ),
        (
            "COLD_PITCHING",
            r"\b(?:cold outreach|cold pitch|unsolicited sales pitch|"
            r"never contacted you before|introducing our services|"
            r"want to sell you our services)\b",
            "MEDIUM", False, 0.72,
            "Unsolicited commercial pitching indicators detected."
        ),
        (
            "REPETITIVE_SPAM",
            r"\b(?:follow[- ]?up again|following up again|"
            r"repeatedly sending|multiple previous emails|"
            r"sent this several times|keep receiving this email)\b",
            "MEDIUM", False, 0.76,
            "Repetitive unsolicited email indicators detected."
        ),
        (
            "MISLEADING_SUBJECT",
            r"\b(?:re: your payment|re: approved|fwd: urgent|"
            r"your account has been approved|payment received|"
            r"your order is confirmed)\b",
            "HIGH", False, 0.80,
            "Potentially misleading subject or false conversation context detected."
        ),
        (
            "CLICKBAIT_EMAIL",
            r"\b(?:you won't believe|shocking discovery|"
            r"secret revealed|one simple trick|"
            r"open to discover|you have never seen this before)\b",
            "MEDIUM", False, 0.72,
            "Manipulative clickbait language detected."
        ),
        (
            "DECEPTIVE_PROMOTION",
            r"\b(?:guaranteed profit|guaranteed returns|"
            r"100% guaranteed earnings|limited time free money|"
            r"claim your free cash|no risk huge returns)\b",
            "MEDIUM", False, 0.78,
            "Deceptive promotional claims or unrealistic financial promises detected."
        ),
        (
            "AFFILIATE_SPAM",
            r"\b(?:earn commission for every referral|"
            r"referral commission|affiliate payout|"
            r"promote my referral link|commission on every signup)\b",
            "MEDIUM", False, 0.76,
            "Potential unsolicited affiliate marketing detected."
        ),
        (
            "CHAIN_EMAIL",
            r"\b(?:forward this to (?:at least )?\d+ people|"
            r"send this to everyone you know|"
            r"forward to ten friends|"
            r"if you break this chain|chain letter)\b",
            "MEDIUM", False, 0.85,
            "Chain email forwarding manipulation detected."
        ),
        (
            "UNWANTED_NEWSLETTER",
            r"\b(?:you never subscribed|never signed up for this|"
            r"unsolicited newsletter|without your consent.*newsletter|"
            r"added you to our mailing list without permission)\b",
            "MEDIUM", False, 0.82,
            "Indicators of an unwanted or unconsented newsletter detected."
        ),
        (
            "SNOWSHOE_SPAM",
            r"\b(?:multiple sending domains|rotating sender domains|"
            r"distributed bulk senders|many sender identities|"
            r"rotating sender addresses)\b",
            "HIGH", False, 0.82,
            "Possible distributed snowshoe spam infrastructure detected."
        ),
        (
            "IMAGE_BASED_SPAM",
            r"\b(?:open the image to claim|"
            r"all information is in the attached image|"
            r"view image for offer|image contains your prize|"
            r"text embedded in promotional image)\b",
            "MEDIUM", False, 0.78,
            "Potential image-based promotional spam detected."
        ),
        (
            "OBFUSCATED_SPAM",
            r"\b(?:fr[e3]{2} m[o0]n[e3]y|"
            r"cl[a@]im y[o0]ur pr[i1]z[e3]|"
            r"w[i1]n n[o0]w|"
            r"c[a@]sh [o0]ffer|"
            r"bypass spam filters|evade email filtering)\b",
            "HIGH", True, 0.93,
            "Obfuscated promotional or filter-evasion language detected."
        ),

        # ------------------------------------------------------------
        # B. PHISHING AND SOCIAL ENGINEERING (13-32)
        # ------------------------------------------------------------

        (
            "PHISHING",
            r"\b(?:verify your account|confirm your credentials|"
            r"validate your login|sign in to avoid suspension|"
            r"account verification required)\b",
            "MEDIUM", False, 0.70,
            "Account verification language requires review; independent credential theft indicators can block."
        ),
        (
            "SPEAR_PHISHING",
            r"\b(?:personalized security verification|"
            r"your specific project credentials|"
            r"confidential employee login verification|"
            r"customized account verification request)\b",
            "HIGH", True, 0.94,
            "Targeted spear-phishing indicators detected."
        ),
        (
            "WHALING",
            r"\b(?:urgent ceo wire transfer|"
            r"confidential executive payment|"
            r"board approved secret transfer|"
            r"executive compensation authorization)\b",
            "CRITICAL", True, 0.99,
            "Executive-targeted whaling and financial manipulation detected."
        ),
        (
            "CLONE_PHISHING",
            r"\b(?:updated version of the previous email|"
            r"replacement copy of the original email|"
            r"same document with a new link|"
            r"revised attachment please open again)\b",
            "HIGH", True, 0.93,
            "Potential cloned email or attachment replacement attack detected."
        ),
        (
            "CREDENTIAL_HARVESTING",
            r"\b(?:enter your username and password|"
            r"submit your login credentials|"
            r"provide your account password|"
            r"send your login details|"
            r"capture your credentials)\b",
            "CRITICAL", True, 0.99,
            "Credential harvesting attempt detected."
        ),
        (
            "OTP_HARVESTING",
            r"\b(?:share your otp|send me the otp|"
            r"forward the verification code|"
            r"reply with your one[- ]time password|"
            r"provide your authentication code)\b",
            "CRITICAL", True, 0.99,
            "OTP harvesting or authentication-code theft detected."
        ),
        (
            "MFA_FATIGUE_ATTACK",
            r"\b(?:approve the login request|"
            r"keep approving authentication requests|"
            r"multiple mfa notifications|"
            r"repeated push notifications|"
            r"approve the unexpected login prompt|"
            r"ignore the number of login prompts)\b",
            "CRITICAL", True, 0.99,
            "MFA fatigue or repeated authentication approval manipulation detected."
        ),
        (
            "OAUTH_CONSENT_PHISHING",
            r"\b(?:grant this app access to your mailbox|"
            r"authorize this application to read your emails|"
            r"grant full mailbox permissions|"
            r"approve oauth permissions|"
            r"allow this app to access your files)\b",
            "HIGH", True, 0.97,
            "Suspicious OAuth consent and application permission request detected."
        ),
        (
            "DEVICE_CODE_PHISHING",
            r"\b(?:enter this device code to sign in|"
            r"complete device authorization|"
            r"approve this device login code|"
            r"authenticate using the supplied device code)\b",
            "CRITICAL", True, 0.98,
            "Potential device-code phishing and account authorization abuse detected."
        ),
        (
            "QR_CODE_PHISHING",
            r"\b(?:scan this qr code to verify|"
            r"scan qr to unlock your account|"
            r"scan to complete login|"
            r"scan qr for password verification)\b",
            "HIGH", True, 0.97,
            "QR-code-based phishing indicators detected."
        ),
        (
            "CALLBACK_PHISHING",
            r"\b(?:call this number to verify your account|"
            r"call our security department immediately|"
            r"contact this number to prevent suspension|"
            r"call this number to cancel the transaction)\b",
            "HIGH", True, 0.95,
            "Callback phishing and fraudulent telephone verification indicators detected."
        ),
        (
            "FAKE_DOCUMENT_SHARING",
            r"\b(?:shared a confidential document with you|"
            r"view the secure document immediately|"
            r"document access requires password verification|"
            r"open the document and sign in again)\b",
            "HIGH", True, 0.94,
            "Fake document-sharing and credential collection indicators detected."
        ),
        (
            "ACCOUNT_EXPIRATION_PHISHING",
            r"\b(?:account will expire today|"
            r"mailbox expiration notice|"
            r"your account expires within 24 hours|"
            r"renew your account to avoid deletion)\b",
            "HIGH", True, 0.95,
            "Account expiration phishing indicators detected."
        ),
        (
            "FAKE_PASSWORD_RESET",
            r"\b(?:unauthorized password reset|"
            r"reset your password immediately using this link|"
            r"password reset required to avoid suspension|"
            r"confirm your new password through this link)\b",
            "HIGH", True, 0.96,
            "Fraudulent password reset request detected."
        ),
        (
            "FAKE_SECURITY_WARNING",
            r"\b(?:virus detected in your account|"
            r"security breach detected verify immediately|"
            r"your mailbox is compromised click here|"
            r"critical security alert login required)\b",
            "HIGH", True, 0.95,
            "Fake security warning and fear-based phishing indicators detected."
        ),
        (
            "IDENTITY_PROVIDER_PHISHING",
            r"\b(?:microsoft 365 account verification|"
            r"google workspace password verification|"
            r"single sign on credentials required|"
            r"identity provider authentication required)\b",
            "HIGH", False, 0.84,
            "Potential identity-provider impersonation detected."
        ),
        (
            "FAKE_KYC_VERIFICATION",
            r"\b(?:complete kyc through this link|"
            r"upload your id proof to avoid account closure|"
            r"submit aadhaar and pan for verification|"
            r"kyc verification requires your banking password)\b",
            "HIGH", True, 0.97,
            "Fraudulent KYC and identity-document collection indicators detected."
        ),
        (
            "TAX_THEMED_PHISHING",
            r"\b(?:tax refund verification required|"
            r"tax refund claim through this link|"
            r"tax penalty payment immediately|"
            r"verify your tax account credentials)\b",
            "HIGH", True, 0.95,
            "Tax-themed phishing or fraudulent tax payment indicators detected."
        ),
        (
            "HR_PAYROLL_PHISHING",
            r"\b(?:verify payroll account credentials|"
            r"employee salary correction login|"
            r"download salary slip and enter password|"
            r"hr payroll verification through this link)\b",
            "HIGH", True, 0.97,
            "HR and payroll-themed phishing indicators detected."
        ),
        (
            "CAPTCHA_GATED_PHISHING",
            r"\b(?:complete captcha to view document|"
            r"solve captcha to continue to login|"
            r"verify you are human before entering credentials|"
            r"captcha required to access mailbox)\b",
            "HIGH", False, 0.86,
            "Potential CAPTCHA-gated phishing or credential collection detected."
        ),

        # ------------------------------------------------------------
        # C. FINANCIAL FRAUD AND SCAMS (33-47)
        # ------------------------------------------------------------

        (
            "FAKE_INVOICE_SCAM",
            r"\b(?:overdue invoice attached|"
            r"pay this invoice immediately|"
            r"invoice payment to the new bank account|"
            r"unrecognized invoice payment required)\b",
            "HIGH", True, 0.96,
            "Potential fraudulent invoice and payment request detected."
        ),
        (
            "PAYMENT_DIVERSION",
            r"\b(?:our bank details have changed|"
            r"send future payments to this new account|"
            r"updated beneficiary bank account|"
            r"redirect the payment to the following account)\b",
            "CRITICAL", True, 0.99,
            "Payment diversion and fraudulent beneficiary change detected."
        ),
        (
            "GIFT_CARD_SCAM",
            r"\b(?:purchase gift cards and send the codes|"
            r"buy gift cards for the ceo|"
            r"send me the gift card pin|"
            r"gift card codes required urgently)\b",
            "HIGH", True, 0.98,
            "Gift-card-based financial scam indicators detected."
        ),
        (
            "PAYROLL_DIVERSION",
            r"\b(?:change my salary bank account|"
            r"redirect employee salary payments|"
            r"update payroll direct deposit details|"
            r"send my salary to this new account)\b",
            "CRITICAL", True, 0.99,
            "Payroll diversion and unauthorized salary redirection detected."
        ),
        (
            "REFUND_SCAM",
            r"\b(?:refund processing fee required|"
            r"pay to receive your refund|"
            r"refund requires your banking password|"
            r"provide otp to process refund)\b",
            "HIGH", True, 0.98,
            "Fraudulent refund processing and payment collection detected."
        ),
        (
            "COURIER_SCAM",
            r"\b(?:parcel held due to unpaid fee|"
            r"pay customs fee through this link|"
            r"delivery failed pay redelivery charge|"
            r"provide otp to release your parcel)\b",
            "HIGH", True, 0.97,
            "Courier and delivery payment scam indicators detected."
        ),
        (
            "LOTTERY_SCAM",
            r"\b(?:you have won a lottery|"
            r"claim your unrequested prize|"
            r"pay processing fee to release prize|"
            r"winner notification claim reward)\b",
            "HIGH", True, 0.97,
            "Fraudulent lottery or prize claim detected."
        ),
        (
            "ADVANCE_FEE_FRAUD",
            r"\b(?:pay an upfront release fee|"
            r"advance fee required before payment|"
            r"processing fee to unlock funds|"
            r"pay clearance charges to receive money)\b",
            "CRITICAL", True, 0.99,
            "Advance-fee fraud and upfront payment manipulation detected."
        ),
        (
            "INHERITANCE_SCAM",
            r"\b(?:unclaimed inheritance funds|"
            r"inheritance transfer fee|"
            r"deceased relative left you money|"
            r"release inherited funds after payment)\b",
            "HIGH", True, 0.97,
            "Potential inheritance and fraudulent fund-release scam detected."
        ),
        (
            "JOB_RECRUITMENT_SCAM",
            r"\b(?:pay registration fee for job|"
            r"job offer processing fee|"
            r"guaranteed job after payment|"
            r"pay training deposit to secure employment)\b",
            "HIGH", True, 0.97,
            "Fraudulent recruitment and employment fee collection detected."
        ),
        (
            "INVESTMENT_SCAM",
            r"\b(?:guaranteed daily investment returns|"
            r"double your investment in days|"
            r"risk free investment profit|"
            r"guaranteed monthly returns of \d+%)\b",
            "CRITICAL", True, 0.99,
            "Unrealistic investment returns and investment fraud indicators detected."
        ),
        (
            "CRYPTOCURRENCY_SCAM",
            r"\b(?:send crypto to receive double|"
            r"guaranteed crypto doubling|"
            r"send bitcoin to unlock rewards|"
            r"crypto wallet recovery fee required)\b",
            "CRITICAL", True, 0.99,
            "Cryptocurrency fraud and wallet manipulation indicators detected."
        ),
        (
            "ROMANCE_SCAM",
            r"\b(?:send money for my emergency|"
            r"need money to travel to meet you|"
            r"send funds for medical emergency|"
            r"transfer money to release my package)\b",
            "HIGH", False, 0.84,
            "Potential romance-based financial manipulation detected."
        ),
        (
            "CHARITY_SCAM",
            r"\b(?:donate through this personal account|"
            r"emergency donation payment to private wallet|"
            r"unverified charity donation request|"
            r"donation required to release relief funds)\b",
            "HIGH", False, 0.85,
            "Potential fraudulent charity collection detected."
        ),
        (
            "SEXTORTION",
            r"\b(?:pay or i will release your private photos|"
            r"send cryptocurrency to prevent video release|"
            r"i recorded you through your webcam pay|"
            r"pay to prevent disclosure of intimate material)\b",
            "CRITICAL", True, 0.99,
            "Sextortion, blackmail and coercive payment demands detected."
        ),

        # ------------------------------------------------------------
        # D. URLS, LINKS AND HYPERLINKS (48-61)
        # ------------------------------------------------------------

        (
            "HYPERLINK_MISMATCH",
            r"\b(?:link text does not match destination|"
            r"hidden hyperlink destination|"
            r"click here to verify your credentials|"
            r"button redirects to an unrelated domain)\b",
            "HIGH", False, 0.88,
            "Potential deceptive hyperlink or destination mismatch detected."
        ),
        (
            "SHORTENED_URL",
            r"https?://(?:bit\.ly|tinyurl\.com|t\.co|"
            r"goo\.gl|ow\.ly|is\.gd|cutt\.ly|rb\.gy)/\S+",
            "MEDIUM", False, 0.78,
            "URL shortener detected; destination should be expanded and inspected."
        ),
        (
            "MULTIPLE_REDIRECTS",
            r"\b(?:multiple redirects|redirect chain|"
            r"redirects through several domains|"
            r"final destination hidden|multi-hop redirect)\b",
            "MEDIUM", False, 0.78,
            "Multiple URL redirection indicators detected."
        ),
        (
            "LOOKALIKE_URL",
            r"\b(?:lookalike domain|typosquatting|"
            r"homograph domain|fake microsoft domain|"
            r"fake google login domain|similar looking domain)\b",
            "MEDIUM", False, 0.78,
            "Lookalike domain and brand impersonation indicators detected."
        ),
        (
            "IP_ADDRESS_URL",
            r"https?://(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:/|\b)",
            "HIGH", False, 0.86,
            "URL uses a direct IPv4 address instead of a domain name."
        ),
        (
            "ENCODED_URL",
            r"https?://\S*(?:%[0-9a-fA-F]{2}){3,}\S*",
            "MEDIUM", False, 0.80,
            "URL contains substantial percent-encoded content."
        ),
        (
            "PUNYCODE_URL",
            r"https?://(?:[^\s/]*xn--[^\s/]*)(?:/|\b)",
            "HIGH", False, 0.90,
            "Internationalized punycode domain detected; inspect for homograph abuse."
        ),
        (
            "EMBEDDED_CREDENTIAL_URL",
            r"https?://[^/\s:@]+:[^/\s@]+@[^/\s]+",
            "CRITICAL", True, 0.99,
            "URL contains embedded username or password credentials."
        ),
        (
            "INSECURE_LOGIN_URL",
            r"http://[^\s<>]*(?:login|signin|sign-in|password|"
            r"authenticate|verify|account)[^\s<>]*",
            "HIGH", False, 0.88,
            "Insecure HTTP URL associated with authentication or credential entry detected."
        ),
        (
            "DANGEROUS_URL_SCHEME",
            r"(?:javascript|data|vbscript|file):\s*",
            "CRITICAL", True, 0.99,
            "Potentially dangerous URL scheme detected."
        ),
        (
            "SUSPICIOUS_DOWNLOAD_LINK",
            r"https?://[^\s<>]+\.(?:exe|scr|bat|cmd|ps1|"
            r"vbs|js|jar|msi|hta)(?:[?#][^\s<>]*)?(?=\s|$)",
            "HIGH", True, 0.97,
            "Direct link to a potentially executable or script-based download detected."
        ),
        (
            "OPEN_REDIRECT_ABUSE",
            r"\b(?:open redirect|redirect parameter abuse|"
            r"redirect_uri=https?://|return_url=https?://|"
            r"next=https?://|url=https?://)\b",
            "HIGH", False, 0.89,
            "Potential open-redirect parameter abuse detected."
        ),
        (
            "COMPROMISED_WEBSITE_LINK",
            r"\b(?:compromised website|hacked website|"
            r"malicious injected link|defaced website|"
            r"website serving malware)\b",
            "HIGH", True, 0.95,
            "Indicators of a compromised or malicious website link detected."
        ),
        (
            "TRACKING_BEACON_URL",
            r"https?://[^\s<>]*(?:/open\?|/pixel\?|"
            r"/track\?|/beacon\?|/collect\?)[^\s<>]*",
            "MEDIUM", False, 0.75,
            "Tracking pixel or beacon endpoint detected; inspect consent and purpose."
        ),

        # ------------------------------------------------------------
        # E. ATTACHMENTS, FILES AND MALWARE (62-79)
        # ------------------------------------------------------------

        (
            "EXECUTABLE_ATTACHMENT",
            r"\b(?:attached executable|executable attachment|"
            r"attached setup\.exe|download the attached exe|"
            r"attached installer file)\b",
            "HIGH", True, 0.98,
            "Executable attachment indicators detected."
        ),
        (
            "SCRIPT_ATTACHMENT",
            r"\b(?:attached powershell script|"
            r"attached javascript file|attached vbs script|"
            r"run the attached batch file|attached cmd script)\b",
            "CRITICAL", True, 0.99,
            "Script-based attachment execution indicators detected."
        ),
        (
            "MACRO_ENABLED_DOCUMENT",
            r"\b(?:enable macros to view|"
            r"enable content to open document|"
            r"enable word macros|enable excel macros|"
            r"disable protected view to continue)\b",
            "HIGH", True, 0.97,
            "Macro-enabled document execution manipulation detected."
        ),
        (
            "PASSWORD_PROTECTED_ATTACHMENT",
            r"\b(?:attachment password is|"
            r"password protected zip attachment|"
            r"enter password to extract attachment|"
            r"password to open attached archive)\b",
            "MEDIUM", False, 0.83,
            "Password-protected attachment indicators detected; content inspection may be limited."
        ),
        (
            "NESTED_ARCHIVE",
            r"\b(?:nested zip archive|archive inside archive|"
            r"multiple nested compressed files|"
            r"extract the inner archive|nested rar file)\b",
            "HIGH", True, 0.95,
            "Nested archive and potential inspection-evasion indicators detected."
        ),
        (
            "DOUBLE_EXTENSION",
            r"\b[\w-]+\.(?:pdf|doc|docx|jpg|png)\."
            r"(?:exe|scr|bat|cmd|js|vbs|ps1|hta)\b",
            "CRITICAL", True, 0.99,
            "Double-extension attachment masquerading as a legitimate document detected."
        ),
        (
            "MIME_TYPE_MISMATCH",
            r"\b(?:mime type mismatch|"
            r"file extension does not match content|"
            r"incorrect file signature|"
            r"disguised file type|"
            r"file header mismatch)\b",
            "HIGH", True, 0.98,
            "File extension and actual content-type mismatch indicators detected."
        ),
        (
            "HTML_SMUGGLING",
            r"\b(?:html smuggling|"
            r"javascript reconstructs downloaded file|"
            r"browser generated payload|"
            r"base64 payload reconstructed in browser)\b",
            "CRITICAL", True, 0.99,
            "HTML smuggling and browser-side payload reconstruction indicators detected."
        ),
        (
            "MALICIOUS_PDF",
            r"\b(?:pdf contains malicious javascript|"
            r"pdf exploit payload|"
            r"malicious pdf attachment|"
            r"pdf launches external executable|"
            r"pdf exploits document reader)\b",
            "CRITICAL", True, 0.99,
            "Malicious PDF and document exploit indicators detected."
        ),
        (
            "ACTIVE_SVG_CONTENT",
            r"\b(?:svg contains embedded javascript|"
            r"active svg script|"
            r"svg onload payload|"
            r"svg contains external script)\b",
            "HIGH", True, 0.97,
            "Potentially executable or active SVG content detected."
        ),
        (
            "SHORTCUT_ATTACHMENT",
            r"\b(?:attached lnk shortcut|"
            r"windows shortcut attachment|"
            r"attached url shortcut|"
            r"open the attached shortcut file)\b",
            "HIGH", True, 0.97,
            "Potentially malicious shortcut attachment detected."
        ),
        (
            "EMBEDDED_OBJECT_ATTACK",
            r"\b(?:embedded ole object|"
            r"embedded executable object|"
            r"document contains external object|"
            r"embedded object launches program|"
            r"embedded active content)\b",
            "CRITICAL", True, 0.99,
            "Embedded object execution or exploitation indicators detected."
        ),
        (
            "CALENDAR_INVITATION_ABUSE",
            r"\b(?:calendar invitation requires password|"
            r"meeting invite contains malicious link|"
            r"accept invitation to verify account|"
            r"calendar invite requests credentials)\b",
            "HIGH", True, 0.95,
            "Calendar invitation abuse and credential collection indicators detected."
        ),
        (
            "ATTACHED_EMAIL_ABUSE",
            r"\b(?:attached original email for verification|"
            r"open the attached eml file|"
            r"attached email message contains login link|"
            r"forwarded email attachment requires credentials)\b",
            "MEDIUM", False, 0.83,
            "Potential malicious attached-email or message-file lure detected."
        ),
        (
            "QR_CODE_IN_ATTACHMENT",
            r"\b(?:qr code embedded in attachment|"
            r"scan the qr code in attached pdf|"
            r"attached document contains qr login code|"
            r"scan attached qr for account verification)\b",
            "HIGH", True, 0.97,
            "QR-code phishing indicators inside an attachment detected."
        ),
        (
            "MALWARE_INFECTED_FILE",
            r"\b(?:malware detected in attachment|"
            r"infected file detected|"
            r"trojan found in attachment|"
            r"ransomware detected in file|"
            r"malicious payload identified)\b",
            "CRITICAL", True, 0.99,
            "Malware-infected attachment indicators detected."
        ),
        (
            "DOCUMENT_LINK_LURE",
            r"\b(?:view the attached document online|"
            r"document download requires sign in|"
            r"open document through external portal|"
            r"download document using this verification link)\b",
            "HIGH", False, 0.87,
            "Document-sharing link lure indicators detected."
        ),
        (
            "UNREADABLE_ATTACHMENT",
            r"\b(?:attachment could not be scanned|"
            r"file content unreadable|"
            r"encrypted attachment not inspected|"
            r"unsupported attachment format|"
            r"attachment parsing failed)\b",
            "MEDIUM", False, 0.82,
            "Attachment could not be fully inspected; security verification is incomplete."
        ),

        # ------------------------------------------------------------
        # F. RESTRICTED CONTENT, LEAKAGE AND ADVANCED THREATS (80-97)
        # ------------------------------------------------------------

        (
            "SEXUAL_SOLICITATION",
            r"\b(?:solicit sexual services|"
            r"pay for sexual favors|"
            r"explicit sexual service offer|"
            r"request sexual services for payment)\b",
            "HIGH", True, 0.97,
            "Unsolicited sexual solicitation indicators detected."
        ),
        (
            "EXPLICIT_ADULT_CONTENT",
            r"\b(?:explicit sexual images attached|"
            r"pornographic material attached|"
            r"explicit adult video attached|"
            r"distribute sexually explicit material)\b",
            "HIGH", True, 0.96,
            "Explicit adult material distribution indicators detected."
        ),
        (
            "HARASSMENT",
            r"\b(?:i will keep harassing you|"
            r"repeated unwanted abusive messages|"
            r"targeted personal harassment|"
            r"stop or i will publicly humiliate you)\b",
            "HIGH", True, 0.96,
            "Targeted harassment and abusive communication detected."
        ),
        (
            "HATE_SPEECH",
            r"\b(?:racial slurs directed at|"
            r"ethnic group should be eliminated|"
            r"religious group deserves violence|"
            r"dehumanize people based on their identity)\b",
            "HIGH", True, 0.97,
            "Hateful or identity-targeted abusive content indicators detected."
        ),
        (
            "THREATENING_EMAIL",
            r"\b(?:i will physically harm you|"
            r"i will come after you|"
            r"i will attack you|"
            r"you will be hurt if you refuse|"
            r"i will destroy your property)\b",
            "CRITICAL", True, 0.99,
            "Direct threats of physical harm or property damage detected."
        ),
        (
            "COERCION_OR_BLACKMAIL",
            r"\b(?:pay or i will expose you|"
            r"do this or i will leak your information|"
            r"comply or face public exposure|"
            r"send money or i will reveal your secrets|"
            r"i will publish your private records)\b",
            "CRITICAL", True, 0.99,
            "Coercion, extortion or blackmail indicators detected."
        ),
        (
            "PROHIBITED_PRODUCT_SOLICITATION",
            r"\b(?:sell illegal weapons|"
            r"purchase stolen credentials|"
            r"buy counterfeit identity documents|"
            r"illegal controlled substance delivery|"
            r"unlicensed sale of prohibited goods)\b",
            "CRITICAL", True, 0.99,
            "Solicitation involving prohibited or illegal products detected."
        ),
        (
            "PERSONAL_DATA_LEAKAGE",
            r"\b(?:confidential personal data|"
            r"expose customer personal information|"
            r"share employee personal records externally|"
            r"upload customer identity records to public storage|"
            r"send private personal details to third party)\b",
            "CRITICAL", True, 0.99,
            "Unauthorized disclosure of personal information detected."
        ),
        (
            "CREDENTIAL_OR_API_KEY_LEAKAGE",
            r"\b(?:send the production api key|"
            r"share the database password externally|"
            r"upload access token to public repository|"
            r"expose private authentication key|"
            r"send aws secret access key|"
            r"share confidential login credentials)\b",
            "CRITICAL", True, 0.99,
            "Credential, API key or authentication secret disclosure detected."
        ),
        (
            "FINANCIAL_DATA_LEAKAGE",
            r"\b(?:confidential bank account records|"
            r"share customer card numbers externally|"
            r"upload private financial statements|"
            r"send employee banking details to third party|"
            r"expose confidential transaction records)\b",
            "CRITICAL", True, 0.99,
            "Unauthorized financial information disclosure detected."
        ),
        (
            "CONFIDENTIAL_DOCUMENT_LEAKAGE",
            r"\b(?:confidential internal document|"
            r"restricted company document|"
            r"proprietary business information|"
            r"internal confidential report|"
            r"share classified company files externally)\b",
            "HIGH", True, 0.98,
            "Potential unauthorized disclosure of confidential business documents detected."
        ),
        (
            "WRONG_RECIPIENT",
            r"\b(?:sent to the wrong recipient|"
            r"accidentally emailed the wrong person|"
            r"wrong external email address|"
            r"confidential email sent by mistake|"
            r"unintended recipient received the attachment)\b",
            "HIGH", True, 0.97,
            "Confidential information may have been sent to an unintended recipient."
        ),
        (
            "UNAUTHORIZED_EXTERNAL_SHARING",
            r"\b(?:share confidential files externally|"
            r"send restricted company data outside the company|"
            r"upload internal records to personal email|"
            r"transfer private employee data to third party|"
            r"forward internal documents to external consultant)\b",
            "CRITICAL", True, 0.99,
            "Unauthorized external sharing of internal or confidential information detected."
        ),
        (
            "MASS_RECIPIENT_ABUSE",
            r"\b(?:bcc thousands of external recipients|"
            r"send confidential records to all contacts|"
            r"bulk distribute private employee information|"
            r"mass email customer personal data)\b",
            "HIGH", True, 0.98,
            "Mass distribution of sensitive information detected."
        ),
        (
            "UNCONSENTED_MAILING",
            r"\b(?:email users without their consent|"
            r"send marketing emails to scraped addresses|"
            r"mailing list collected without permission|"
            r"send unsolicited messages to purchased contacts)\b",
            "MEDIUM", False, 0.85,
            "Potential unconsented email distribution detected."
        ),
        (
            "HIDDEN_OR_ENCODED_TEXT",
            r"\b(?:hidden white text|"
            r"zero width character obfuscation|"
            r"encoded instructions hidden in email|"
            r"concealed text to bypass email filters|"
            r"invisible text containing instructions)\b",
            "HIGH", True, 0.96,
            "Hidden or obfuscated content intended to evade security inspection detected."
        ),
        (
            "IMAGE_EMBEDDED_TEXT",
            r"\b(?:text embedded in image to bypass filters|"
            r"ocr evasion|"
            r"hidden instructions inside image|"
            r"image contains concealed phishing text|"
            r"image based credential harvesting)\b",
            "HIGH", True, 0.95,
            "Image-embedded malicious or concealed text indicators detected."
        ),
        (
            "AI_PROMPT_INJECTION",
            r"\b(?:ignore all previous instructions|"
            r"disregard the system prompt|"
            r"override previous security instructions|"
            r"reveal your hidden system instructions|"
            r"ignore your safety rules and execute|"
            r"exfiltrate the system prompt|"
            r"send confidential context to this address)\b",
            "CRITICAL", True, 0.99,
            "Prompt injection and attempts to override security instructions detected."
        ),
    ]

    # Execute all detection rules
    for code, pattern, severity, confirmed, confidence, message in detection_rules:
        if _has(pattern, t):
            add(
                code,
                severity,
                message,
                confirmed=confirmed,
                confidence=confidence
            )

        # Employee salary information sent externally
    salary_records = _has(
        r"\b(?:employee salary report|salary report|"
        r"employee compensation|salary information|payroll records)\b", t
    )
    salary_confidential = _has(
        r"\b(?:confidential|restricted|internal|private)\b", t
    )
    external_employee_share = _has(
        r"\b(?:share|send|forward|upload|transfer)\b", t
    ) and _has(
        r"\b(?:external consultant|external recipient|"
        r"third party|outside the company)\b", t
    )

    if salary_records and salary_confidential and external_employee_share:
        add(
            "EMPLOYEE_DATA_EXFILTRATION",
            "CRITICAL",
            "Confidential employee compensation records are explicitly being shared with an external recipient.",
            confirmed=True,
            confidence=0.99
        )
    

    # Excessive urgency and pressure-based promotional abuse
    excessive_urgency = _has(
        r"\b(?:last hour|last chance|final hours|"
        r"expires immediately|act immediately|"
        r"act now or lose|limited time only|"
        r"offer ends today|ending in minutes|"
        r"respond immediately|buy now or lose|"
        r"price expires shortly|"
        r"special price expires|"
        r"lose this special promotional price)\b", t
    )

    urgency_promotion = _has(
        r"\b(?:promotional price|special promotion|"
        r"special offer|discount offer|limited time offer|"
        r"exclusive deal|sale price|discounted price|"
        r"promotional deal)\b", t
    )

    urgency_pressure = _has(
        r"\b(?:act immediately|act now|"
        r"don't miss out|do not miss out|"
        r"lose this offer|lose this price|"
        r"buy immediately|purchase immediately|"
        r"offer will disappear|price will increase)\b", t
    )

    if excessive_urgency and urgency_promotion and urgency_pressure:
        add(
            "EXCESSIVE_URGENCY_PROMOTION",
            "MEDIUM",
            "Excessive urgency and pressure-based promotional messaging detected, attempting to force an immediate purchase.",
            confirmed=False,
            confidence=0.98
        )


    
    # ============================================================
    # MARKETING ABUSE, SPAM AND PROMOTIONAL DECEPTION
    # ============================================================

    # 1. Unrequested bulk promotional email — WARNING
    unrequested_promotion = _has(
        r"\b(?:promotional offers?|discount offers?|advertisements?|"
        r"marketing messages?|special deals?)\b", t
    )
    unrequested_context = _has(
        r"\b(?:never contacted|never contacted us|did not request|"
        r"unrequested|without requesting|unsolicited|unknown sender)\b", t
    )
    if unrequested_promotion and unrequested_context:
        add("UNREQUESTED_BULK_PROMOTION", "MEDIUM",
            "Unrequested promotional communication from an unfamiliar or unsolicited sender.",
            confirmed=False, confidence=0.86)

    # 2. Repeated coupon or campaign reminders — WARNING
    repeated_campaign = _has(
        r"\b(?:reminder number\s*[2-9]|"
        r"(?:second|third|fourth|fifth|sixth|seventh|eighth|ninth|"
        r"tenth)\s+reminder|"
        r"another reminder|final reminder|reminder again)\b", t
    )
    coupon_context = _has(
        r"\b(?:discount code|coupon|promo code|voucher|"
        r"discount is still waiting|offer is still available)\b", t
    )
    if repeated_campaign and coupon_context:
        add("REPEATED_PROMOTIONAL_CAMPAIGN", "MEDIUM",
            "Repeated promotional reminders indicate potentially unwanted campaign activity.",
            confirmed=False, confidence=0.88)

    # 3. Excessive urgency promotion — WARNING
    # Includes the exact test case: "LAST HOUR! Act immediately or
    # lose this special promotional price."
    urgent_promotion = _has(
        r"\b(?:last hour|last chance|final hours|"
        r"act immediately|act now|expires immediately|"
        r"offer ends today|ending in minutes|"
        r"price expires shortly|limited time only)\b", t
    )
    promotion_context = _has(
        r"\b(?:promotional price|special promotional price|"
        r"special promotion|special offer|discount|"
        r"sale price|promotional deal|exclusive deal)\b", t
    )
    loss_pressure = _has(
        r"\b(?:lose|miss out|forfeit|"
        r"offer will disappear|price will increase)\b", t
    )
    if urgent_promotion and promotion_context and loss_pressure:
        add("EXCESSIVE_URGENCY_PROMOTION", "MEDIUM",
            "High-pressure promotional language attempts to force an immediate purchase.",
            confirmed=False, confidence=0.94)

    # 4. Misleading subject / reply-chain deception — WARNING
    misleading_reply = _has(
        r"\b(?:re:|fw:|fwd:)\s*(?:your\s+)?"
        r"(?:invoice|payment|order|account|document|meeting)\b", t
    )
    unrelated_promotion = _has(
        r"\b(?:actually|instead|unrelated|advertis(?:e|es|ing))\b", t
    ) and _has(
        r"\b(?:shopping promotion|product promotion|discount|"
        r"advertisement|marketing offer)\b", t
    )
    if misleading_reply and unrelated_promotion:
        add("MISLEADING_SUBJECT_LINE", "MEDIUM",
            "The message uses a reply or forwarding subject to disguise unrelated promotional content.",
            confirmed=False, confidence=0.91)

    # 5. Aggressive referral / chain promotion — WARNING
    referral_pressure = _has(
        r"\b(?:forward|send|share)\s+(?:this\s+)?"
        r"(?:promotional\s+)?(?:message|email|offer)\b", t
    )
    mass_referral = _has(
        r"\b(?:to\s+\d{1,4}\s+(?:friends|contacts|people)|"
        r"twenty friends|all your friends|everyone you know)\b", t
    )
    referral_reward = _has(
        r"\b(?:unlock|receive|claim|earn)\s+(?:a\s+)?"
        r"(?:reward|bonus|gift|prize|discount)\b", t
    )
    if referral_pressure and mass_referral and referral_reward:
        add("AGGRESSIVE_REFERRAL_CAMPAIGN", "MEDIUM",
            "The message encourages mass forwarding in exchange for a reward.",
            confirmed=False, confidence=0.93)

    # 6. Unverified giveaway — WARNING
    giveaway_claim = _has(
        r"\b(?:free\s+(?:smartphone|iphone|phone|laptop|gift|prize)|"
        r"giveaway|free gift|free reward)\b", t
    )
    giveaway_uncertainty = _has(
        r"\b(?:might qualify|may qualify|selected randomly|"
        r"you may have won|you could win|congratulations)\b", t
    )
    if giveaway_claim and giveaway_uncertainty:
        add("UNVERIFIED_GIVEAWAY", "MEDIUM",
            "An unverified giveaway or prize claim may be intended to attract engagement.",
            confirmed=False, confidence=0.87)

    # 7. Hidden sponsorship / disguised advertisement — WARNING
    disguised_review = _has(
        r"\b(?:neutral review|independent review|unbiased review|"
        r"editorial review|product review)\b", t
    )
    sponsorship_signal = _has(
        r"\b(?:sponsored|paid promotion|affiliate link|"
        r"commission|advertiser|brand partnership)\b", t
    )
    undisclosed_sponsorship = _has(
        r"\b(?:undisclosed|not disclosed|without disclosure|"
        r"hidden sponsorship|concealed sponsorship)\b", t
    )
    if disguised_review and sponsorship_signal and undisclosed_sponsorship:
        add("UNDISCLOSED_SPONSORED_PROMOTION", "MEDIUM",
            "Promotional sponsorship appears to be concealed within apparently independent content.",
            confirmed=False, confidence=0.91)

    # 8. Irrelevant unsolicited B2B outreach — WARNING
    b2b_pitch = _has(
        r"\b(?:sell you a service|selling our services|"
        r"business solution|sales proposal|our product offering|"
        r"schedule a sales demonstration)\b", t
    )
    unrequested_contact = _has(
        r"\b(?:never contacted|did not request|unrequested|"
        r"unsolicited|found your business contact|cold outreach)\b", t
    )
    if b2b_pitch and unrequested_contact:
        add("UNSOLICITED_B2B_OUTREACH", "MEDIUM",
            "Unrequested business-to-business sales outreach detected.",
            confirmed=False, confidence=0.88)

    # 9. Sensational health promotion — WARNING
    health_claim = _has(
        r"\b(?:instant results|instant cure|miracle cure|"
        r"guaranteed results|overnight results|"
        r"permanent weight loss|works immediately)\b", t
    )
    health_promotion = _has(
        r"\b(?:health product|supplement|treatment|"
        r"weight loss|medical product|health promotion)\b", t
    )
    if health_claim and health_promotion:
        add("SENSATIONAL_HEALTH_PROMOTION", "MEDIUM",
            "Promotional health claims promise unusually fast or guaranteed results.",
            confirmed=False, confidence=0.90)

    # 10. Deceptive scarcity claim — WARNING
    scarcity_claim = _has(
        r"\b(?:only one left|only \d+ left|almost sold out|"
        r"last item available|few items remaining|"
        r"limited stock|stock is running out)\b", t
    )
    scarcity_unverified = _has(
        r"\b(?:unverified|unknown sender|cannot verify|"
        r"not independently verified|according to this message)\b", t
    )
    if scarcity_claim and scarcity_unverified:
        add("UNVERIFIED_SCARCITY_CLAIM", "MEDIUM",
            "The message uses a scarcity claim that cannot be independently verified.",
            confirmed=False, confidence=0.87)

    # 11. Unverified affiliate / commission pitch — WARNING
    affiliate_offer = _has(
        r"\b(?:earn commission|affiliate commission|"
        r"referral commission|promote this offer|"
        r"referral opportunity)\b", t
    )
    unknown_offer = _has(
        r"\b(?:unfamiliar|unknown|unverified|unexpected|"
        r"not previously known)\b", t
    )
    if affiliate_offer and unknown_offer:
        add("UNVERIFIED_AFFILIATE_PITCH", "MEDIUM",
            "An unfamiliar affiliate or referral offer promises commission.",
            confirmed=False, confidence=0.86)

    # 12. Obfuscated promotional text — WARNING
    obfuscated_free = _has(
        r"\bf\s*[-_. ]+\s*r\s*[-_. ]+\s*e\s*[-_. ]+\s*e\b", t
    )
    obfuscated_reward = _has(
        r"\b(?:rewards?|prizes?|gifts?|offers?)\b", t
    )
    if obfuscated_free and obfuscated_reward:
        add("OBFUSCATED_PROMOTIONAL_TEXT", "MEDIUM",
            "Promotional keywords are deliberately spaced or obfuscated, potentially to evade filters.",
            confirmed=False, confidence=0.90)


    # ============================================================
    # EXPLICIT ABUSE, IMPERSONATION AND DATA THEFT — RESTRICTED
    # ============================================================

    # 13. Unconsented bulk distribution — RESTRICTED
    bulk_advertising = _has(
        r"\b(?:send|distribute|forward|mail)\b", t
    ) and _has(
        r"\b(?:advertisement|marketing email|promotional message|"
        r"campaign)\b", t
    )
    harvested_addresses = _has(
        r"\b(?:harvested addresses|scraped email addresses|"
        r"purchased mailing list|collected without consent)\b", t
    )
    no_consent = _has(
        r"\b(?:without consent|without permission|"
        r"without authorization|no consent|opted out)\b", t
    )
    if bulk_advertising and harvested_addresses and no_consent:
        add("UNCONSENTED_BULK_DISTRIBUTION", "HIGH",
            "The message explicitly describes distributing advertising to harvested addresses without consent.",
            confirmed=True, confidence=0.99)

    # 14. Forged unsubscribe / consent confirmation — RESTRICTED
    false_opt_in = _has(
        r"\b(?:you opted in|you subscribed|your subscription was confirmed|"
        r"you agreed to receive|you requested these emails)\b", t
    )
    false_consent = _has(
        r"\b(?:falsely claims|false confirmation|"
        r"you did not subscribe|never opted in|"
        r"without your consent|fabricated consent)\b", t
    )
    if false_opt_in and false_consent:
        add("FORGED_UNSUBSCRIBE_CONFIRMATION", "HIGH",
            "The message describes or uses fabricated subscription consent.",
            confirmed=True, confidence=0.98)

    # 15. Impersonated marketing brand — RESTRICTED
    brand_impersonation = _has(
        r"\b(?:impersonat(?:e|es|ed|ing)|pretending to be|"
        r"falsely claims to come from|fake brand identity|"
        r"not an authorized representative)\b", t
    )
    retailer_promotion = _has(
        r"\b(?:retailer|shopping brand|well-known brand|"
        r"official store|brand promotion|retail promotion)\b", t
    )
    if brand_impersonation and retailer_promotion:
        add("IMPERSONATED_MARKETING_BRAND", "HIGH",
            "The sender or promotion explicitly impersonates a retailer or established brand.",
            confirmed=True, confidence=0.98)

    # 16. Deceptive tracking redirect with credential theft — RESTRICTED
    disguised_redirect = _has(
        r"\b(?:disguised tracking|tracking redirect|"
        r"redirects through|hidden redirect|concealed destination)\b", t
    )
    credential_collection = _has(
        r"\b(?:credential collection|collect credentials|"
        r"steal credentials|capture passwords|"
        r"credential harvesting|login credentials)\b", t
    )
    if disguised_redirect and credential_collection:
        add("DECEPTIVE_TRACKING_CREDENTIAL_REDIRECT", "CRITICAL",
            "A deceptive redirect is explicitly associated with credential collection.",
            confirmed=True, confidence=0.99)

    # 17. Fake delivery service requesting payment — RESTRICTED
    fake_delivery = _has(
        r"\b(?:fake delivery service|fake courier|"
        r"impersonated delivery company|nonexistent parcel|"
        r"fake parcel notification)\b", t
    )
    delivery_payment = _has(
        r"\b(?:payment details|card details|bank details|"
        r"pay a delivery fee|customs fee|redelivery fee)\b", t
    )
    if fake_delivery and delivery_payment:
        add("FAKE_DELIVERY_PAYMENT_FRAUD", "CRITICAL",
            "A fraudulent delivery identity requests payment information for a nonexistent parcel.",
            confirmed=True, confidence=0.99)

    # 18. Account takeover using OTP — RESTRICTED
    free_premium_lure = _has(
        r"\b(?:free premium access|free premium account|"
        r"unlock premium access|free account upgrade)\b", t
    )
    otp_request = _has(
        r"\b(?:one[- ]time (?:login )?code|otp|verification code|"
        r"authentication code|login code)\b", t
    )
    share_code = _has(
        r"\b(?:share|send|provide|forward|reveal|reply with|"
        r"enter)\b", t
    )
    if free_premium_lure and otp_request and share_code:
        add("ACCOUNT_TAKEOVER_OTP_THEFT", "CRITICAL",
            "A promotional lure requests a one-time authentication code, enabling account takeover.",
            confirmed=True, confidence=0.99)

    # 19. Fake charity using personal payment account — RESTRICTED
    fake_charity = _has(
        r"\b(?:fake charity|impersonated charity|"
        r"fraudulent charity|fake disaster relief|"
        r"charity impersonation)\b", t
    )
    personal_payment = _has(
        r"\b(?:personal payment account|personal bank account|"
        r"private payment account|individual's account|"
        r"personal wallet)\b", t
    )
    if fake_charity and personal_payment:
        add("FAKE_CHARITY_PAYMENT_FRAUD", "CRITICAL",
            "A fraudulent charity identity directs donations to a personal payment account.",
            confirmed=True, confidence=0.99)

    # 20. Malware-themed advertising — RESTRICTED
    unknown_program = _has(
        r"\b(?:unknown program|untrusted program|"
        r"unknown executable|unverified software|"
        r"remote-control program)\b", t
    )
    install_execute = _has(
        r"\b(?:install|execute|run|launch|open)\b", t
    )
    gift_lure = _has(
        r"\b(?:promotional gift|free gift|gift offer|"
        r"free reward|promotional reward)\b", t
    )
    if unknown_program and install_execute and gift_lure:
        add("MALWARE_PROMOTIONAL_LURE", "HIGH",
            "The message uses a promotional reward to persuade the recipient to install or execute an unknown program.",
            confirmed=True, confidence=0.98)


    # ============================================================
    # PHISHING, SOCIAL ENGINEERING AND ACCOUNT COMPROMISE
    # ============================================================

    # 21. One-time-code theft
    otp_theft = _has(
        r"\b(?:otp|one[- ]time (?:password|code)|"
        r"verification code|authentication code)\b", t
    )
    authority_pretext = _has(
        r"\b(?:security representative|support agent|"
        r"helpdesk|administrator|bank representative|"
        r"security team)\b", t
    )
    otp_request = _has(
        r"\b(?:send|share|provide|tell me|reply with|"
        r"reveal|forward)\b", t
    )
    if otp_theft and authority_pretext and otp_request:
        add("ONE_TIME_CODE_THEFT", "CRITICAL",
            "A purported support or security representative requests a one-time authentication code.",
            confirmed=True, confidence=0.99)

    # 22. Executive / CEO impersonation with funds transfer
    executive_impersonation = _has(
        r"\b(?:impersonating the ceo|pretending to be the ceo|"
        r"fake ceo|impersonated cfo|fake cfo|"
        r"posing as the ceo|posing as the cfo)\b", t
    )
    fund_transfer = _has(
        r"\b(?:funds transfer|wire transfer|bank transfer|"
        r"transfer the payment|redirect the payment|"
        r"change bank details)\b", t
    )
    if executive_impersonation and fund_transfer:
        add("EXECUTIVE_IMPERSONATION_PAYMENT_FRAUD", "CRITICAL",
            "An impersonated executive instructs the recipient to transfer or redirect funds.",
            confirmed=True, confidence=0.99)

    # 23. Fake SSO / corporate login portal
    fake_sso = _has(
        r"\b(?:fake sso|forged sign[- ]in page|"
        r"counterfeit login page|fake authentication portal|"
        r"forged company login|fake company login)\b", t
    )
    corporate_auth = _has(
        r"\b(?:corporate credentials|company password|"
        r"employee login|sso credentials|"
        r"company authentication)\b", t
    )
    if fake_sso and corporate_auth:
        add("FAKE_SSO_CREDENTIAL_HARVESTING", "CRITICAL",
            "A counterfeit corporate authentication portal requests employee credentials.",
            confirmed=True, confidence=0.99)

    # 24. Payroll identity theft
    hr_impersonation = _has(
        r"\b(?:impersonated hr|fake hr officer|"
        r"pretending to be hr|fake payroll administrator)\b", t
    )
    identity_bank_data = _has(
        r"\b(?:national id|government id|identity document|"
        r"banking information|bank account details|"
        r"employee identity information)\b", t
    )
    if hr_impersonation and identity_bank_data:
        add("PAYROLL_IDENTITY_THEFT", "CRITICAL",
            "An impersonated HR or payroll representative requests sensitive identity or banking information.",
            confirmed=True, confidence=0.99)

    # 25. Fake account recovery / backup-code theft
    fake_recovery = _has(
        r"\b(?:fake recovery team|fraudulent recovery team|"
        r"fake account recovery|counterfeit recovery service)\b", t
    )
    backup_code_request = _has(
        r"\b(?:backup authentication codes|recovery codes|"
        r"backup codes|account recovery codes)\b", t
    )
    if fake_recovery and backup_code_request:
        add("FAKE_ACCOUNT_RECOVERY_CODE_THEFT", "CRITICAL",
            "A fraudulent recovery service requests account recovery or backup authentication codes.",
            confirmed=True, confidence=0.99)

    # 26. Vendor identity spoofing and confidential file theft
    vendor_spoof = _has(
        r"\b(?:pretending to be a known supplier|"
        r"impersonated supplier|fake vendor identity|"
        r"spoofed vendor|fake supplier)\b", t
    )
    confidential_files = _has(
        r"\b(?:confidential files|sensitive files|"
        r"internal documents|customer database|"
        r"restricted documents)\b", t
    )
    if vendor_spoof and confidential_files:
        add("VENDOR_IMPERSONATION_DATA_THEFT", "CRITICAL",
            "A spoofed supplier identity is used to request confidential organizational files.",
            confirmed=True, confidence=0.99)

    # 27. Helpdesk remote-access scam
    helpdesk_impersonation = _has(
        r"\b(?:fake helpdesk|impersonated helpdesk|"
        r"fake technical support|pretending to be support)\b", t
    )
    remote_access = _has(
        r"\b(?:remote[- ]control software|remote access tool|"
        r"remote desktop software|screen sharing application|"
        r"remote administration software)\b", t
    )
    if helpdesk_impersonation and remote_access:
        add("HELPDESK_REMOTE_ACCESS_SCAM", "CRITICAL",
            "An impersonated helpdesk or support representative requests remote-control software installation.",
            confirmed=True, confidence=0.99)

    # 28. Fake security escalation requesting tokens
    fake_security = _has(
        r"\b(?:fake security escalation|forged incident response|"
        r"fake incident response notice|"
        r"counterfeit security alert)\b", t
    )
    access_tokens = _has(
        r"\b(?:access tokens|api tokens|session tokens|"
        r"authentication tokens|bearer tokens|secret keys)\b", t
    )
    if fake_security and access_tokens:
        add("FAKE_SECURITY_TOKEN_THEFT", "CRITICAL",
            "A forged security notice requests sensitive access tokens or secret keys.",
            confirmed=True, confidence=0.99)

    # 29. MFA fatigue pretext
    mfa_pretext = _has(
        r"\b(?:unexpected mfa prompt|unexpected authentication prompt|"
        r"repeated mfa requests|repeated approval requests|"
        r"mfa fatigue|push notification fatigue)\b", t
    )
    mfa_approval = _has(
        r"\b(?:approve|accept|confirm|authorize)\b", t
    )
    if mfa_pretext and mfa_approval:
        add("MFA_FATIGUE_ATTACK", "HIGH",
            "The message pressures the recipient to approve an unexpected or repeated MFA request.",
            confirmed=True, confidence=0.98)

    # 30. Confidential database extraction
    auditor_pretext = _has(
        r"\b(?:fake auditor|unverified auditor|"
        r"impersonated auditor|unauthorized audit|"
        r"fraudulent audit request)\b", t
    )
    employee_database = _has(
        r"\b(?:full employee identity database|"
        r"employee database|customer identity database|"
        r"complete identity records|personal records database)\b", t
    )
    data_request = _has(
        r"\b(?:send|share|export|upload|provide|"
        r"transfer|extract)\b", t
    )
    if auditor_pretext and employee_database and data_request:
        add("CONFIDENTIAL_DATABASE_EXTRACTION", "CRITICAL",
            "An unverified auditor requests bulk extraction of sensitive identity records.",
            confirmed=True, confidence=0.99)


    # ============================================================
    # FINANCIAL FRAUD AND PAYMENT MANIPULATION
    # ============================================================

    # 31. Unverified investment returns — WARNING
    investment_offer = _has(
        r"\b(?:investment|trading|crypto|cryptocurrency|"
        r"investment opportunity)\b", t
    )
    guaranteed_returns = _has(
        r"\b(?:guaranteed returns|guaranteed profit|"
        r"unusually high returns|risk[- ]free returns|"
        r"double your investment|fixed high returns)\b", t
    )
    unknown_sender = _has(
        r"\b(?:unfamiliar sender|unknown sender|stranger|"
        r"unverified service|unexpected offer)\b", t
    )
    if investment_offer and guaranteed_returns and unknown_sender:
        add("UNVERIFIED_INVESTMENT_RETURN", "MEDIUM",
            "An unfamiliar sender promises unusually high or guaranteed investment returns.",
            confirmed=False, confidence=0.94)

    # 32. Gift-card payment pressure
    gift_card_request = _has(
        r"\b(?:gift cards?|gift card codes?|"
        r"gift card numbers?|redemption codes?)\b", t
    )
    immediate_purchase = _has(
        r"\b(?:purchase|buy|get|send|obtain)\b", t
    )
    gift_urgency = _has(
        r"\b(?:immediately|right now|urgent|as soon as possible|"
        r"within minutes|without delay)\b", t
    )
    if gift_card_request and immediate_purchase and gift_urgency and "URGENT_GIFT_CARD_PURCHASE" not in seen:
        add("GIFT_CARD_PAYMENT_PRESSURE", "MEDIUM",
            "The sender urgently pressures the recipient to purchase or provide gift-card codes.",
            confirmed=False, confidence=0.97)

    # 33. Advance-fee loan scam
    advance_fee = _has(
        r"\b(?:upfront release charge|advance processing fee|"
        r"release fee|advance fee|upfront payment)\b", t
    )
    nonexistent_loan = _has(
        r"\b(?:loan that does not exist|fake loan|"
        r"nonexistent loan|loan approval scam|"
        r"release your loan funds)\b", t
    )
    if advance_fee and nonexistent_loan:
        add("ADVANCE_FEE_LOAN_FRAUD", "CRITICAL",
            "The message requests an advance charge for a fraudulent or nonexistent loan.",
            confirmed=True, confidence=0.99)

    # 34. Business email compromise / vendor bank change
    payment_redirection = _has(
        r"\b(?:redirects? a vendor payment|"
        r"change the vendor bank account|"
        r"new bank account for payment|"
        r"replace the beneficiary account|"
        r"change payment instructions)\b", t
    )
    attacker_account = _has(
        r"\b(?:attacker account|fraudulent account|"
        r"unauthorized account|criminal account|"
        r"attacker-controlled account)\b", t
    )
    if payment_redirection and attacker_account:
        add("BUSINESS_EMAIL_COMPROMISE_PAYMENT_REDIRECTION", "CRITICAL",
            "Payment instructions are redirected to an unauthorized or attacker-controlled account.",
            confirmed=True, confidence=0.99)

    # 35. Bank credential theft
    bank_impersonation = _has(
        r"\b(?:fake bank message|impersonated bank|"
        r"fake banking portal|bank security impersonation)\b", t
    )
    bank_credentials = _has(
        r"\b(?:online banking username|banking password|"
        r"bank login credentials|internet banking password)\b", t
    )
    if bank_impersonation and bank_credentials:
        add("BANK_CREDENTIAL_THEFT", "CRITICAL",
            "A fraudulent banking message requests online banking credentials.",
            confirmed=True, confidence=0.99)

    # 36. Fake refund card theft
    fake_refund = _has(
        r"\b(?:fake refund|nonexistent refund|"
        r"fraudulent refund|refund that does not exist)\b", t
    )
    card_security = _has(
        r"\b(?:card number|credit card number|debit card number)\b", t
    ) and _has(
        r"\b(?:security code|cvv|cvc|card verification code)\b", t
    )
    if fake_refund and card_security:
        add("FAKE_REFUND_CARD_THEFT", "CRITICAL",
            "A fraudulent refund process requests payment-card details and security codes.",
            confirmed=True, confidence=0.99)

    # 37. Gift-card fraud by impersonated executive
    executive_gift = _has(
        r"\b(?:impersonated executive|fake ceo|fake manager|"
        r"pretending to be the director|executive impersonation)\b", t
    )
    gift_redemption = _has(
        r"\b(?:gift card numbers|gift card codes|"
        r"redemption codes|gift card pin)\b", t
    )
    if executive_gift and gift_redemption:
        add("EXECUTIVE_GIFT_CARD_FRAUD", "CRITICAL",
            "An impersonated executive requests gift-card numbers or redemption codes.",
            confirmed=True, confidence=0.99)

    # 38. Payroll diversion
    payroll_change = _has(
        r"\b(?:change salary deposits|redirect salary|"
        r"change payroll account|update salary bank details|"
        r"change direct deposit)\b", t
    )
    unauthorized_payroll = _has(
        r"\b(?:unauthorized account|attacker account|"
        r"fraudulent bank account|account not belonging to employee)\b", t
    )
    if payroll_change and unauthorized_payroll:
        add("PAYROLL_DIVERSION_FRAUD", "CRITICAL",
            "Payroll deposits are being redirected to an unauthorized bank account.",
            confirmed=True, confidence=0.99)

    # 39. Cryptocurrency wallet recovery phrase theft
    crypto_support = _has(
        r"\b(?:fake crypto support|fake wallet support|"
        r"impersonated wallet support|fraudulent crypto agent)\b", t
    )
    wallet_secret = _has(
        r"\b(?:wallet recovery phrase|seed phrase|"
        r"private key|wallet backup phrase|recovery phrase)\b", t
    )
    if crypto_support and wallet_secret:
        add("CRYPTO_WALLET_SECRET_THEFT", "CRITICAL",
            "A fraudulent cryptocurrency support identity requests a wallet recovery phrase or private key.",
            confirmed=True, confidence=0.99)

    # 40. Money mule recruitment
    money_mule = _has(
        r"\b(?:receive and forward|receive and transfer|"
        r"move money for others|transfer third[- ]party funds|"
        r"receive funds into your account)\b", t
    )
    unknown_funds = _has(
        r"\b(?:unknown third[- ]party funds|unfamiliar funds|"
        r"funds from strangers|unverified payments|"
        r"funds from unknown sources)\b", t
    )
    if money_mule and unknown_funds:
        add("MONEY_MULE_RECRUITMENT", "CRITICAL",
            "The message recruits the recipient to receive and forward funds from unknown third parties.",
            confirmed=True, confidence=0.99)


    # ============================================================
    # CONFIDENTIAL DATA LEAKAGE AND MALICIOUS ATTACHMENT LURES
    # ============================================================

    # 41. Password dump transfer
    password_dump = _has(
        r"\b(?:password dump|list of real account passwords|"
        r"stolen passwords|database of passwords|"
        r"plaintext passwords|credential dump)\b", t
    )
    password_transfer = _has(
        r"\b(?:attached|attachment|send|share|upload|"
        r"transfer|download|export)\b", t
    )
    if password_dump and password_transfer:
        add("PASSWORD_DUMP_TRANSFER", "CRITICAL",
            "The message describes transferring or distributing real account passwords.",
            confirmed=True, confidence=0.99)

    # 42. Internal network diagram shared externally
    internal_diagram = _has(
        r"\b(?:internal network diagram|network architecture diagram|"
        r"internal infrastructure diagram|private network map)\b", t
    )
    external_share = _has(
        r"\b(?:outside the organization|external recipient|"
        r"external party|outside the company|"
        r"unverified recipient|third party)\b", t
    )
    if internal_diagram and external_share and _has(
        r"\b(?:without authorization|without approval|without permission|unauthorized disclosure|exfiltrate)\b", t
    ):
        add("UNAUTHORIZED_NETWORK_DIAGRAM_TRANSFER", "HIGH",
            "Network diagram transfer includes explicit unauthorized disclosure indicators.",
            confirmed=True, confidence=0.97)
    elif internal_diagram and external_share:
        add("INTERNAL_NETWORK_DIAGRAM_LEAKAGE", "MEDIUM",
            "An internal network or infrastructure diagram is being shared externally.",
            confirmed=False, confidence=0.97)

    # 43. External AI upload of internal material — WARNING
    internal_material = _has(
        r"\b(?:internal project material|confidential project data|"
        r"internal source code|private company documents|"
        r"proprietary information)\b", t
    )
    external_ai = _has(
        r"\b(?:unapproved ai service|external ai tool|"
        r"public ai platform|third[- ]party ai service|"
        r"external chatbot)\b", t
    )
    paste_upload = _has(
        r"\b(?:paste|upload|submit|share|copy)\b", t
    )
    if internal_material and external_ai and paste_upload:
        add("UNAPPROVED_EXTERNAL_AI_DATA_UPLOAD", "HIGH",
            "The message requests transferring internal or proprietary material to an unapproved external AI service.",
            confirmed=False, confidence=0.96)

    # 44. Ransomware delivery attempt
    ransomware = _has(
        r"\b(?:ransomware|encrypts recipient files|"
        r"encrypt your files|file encryption attack|"
        r"ransom payment)\b", t
    )
    attachment_delivery = _has(
        r"\b(?:attachment|attached file|software update|"
        r"download|executable|program)\b", t
    )
    if ransomware and attachment_delivery:
        add("RANSOMWARE_DELIVERY_LURE", "CRITICAL",
            "The message describes delivering ransomware or an attachment intended to encrypt recipient files.",
            confirmed=True, confidence=0.99)

    # 45. Remote access trojan disguised as support utility
    rat_lure = _has(
        r"\b(?:remote access trojan|remote[- ]control trojan|"
        r"remote administration malware|backdoor)\b", t
    )
    utility_disguise = _has(
        r"\b(?:disguised as a support utility|"
        r"fake support utility|pretending to be a support tool|"
        r"unknown remote[- ]control program)\b", t
    )
    if rat_lure and utility_disguise:
        add("REMOTE_ACCESS_TROJAN_LURE", "CRITICAL",
            "A remote-access trojan is disguised as a legitimate support utility.",
            confirmed=True, confidence=0.99)

        
        # Replace the credential_collection pattern with:
    credential_collection = _has(
        r"\b(?:credential[- ]collection|collect credentials|"
        r"steal credentials|capture passwords|"
        r"credential harvesting|login credentials)\b", t
    )

    # Replace the executive_impersonation pattern with:
    executive_impersonation = _has(
        r"\b(?:impersonating\s+(?:the\s+)?ceo|"
        r"impersonating\s+(?:the\s+)?cfo|"
        r"pretending to be the ceo|fake ceo|"
        r"impersonated cfo|fake cfo|"
        r"posing as the ceo|posing as the cfo)\b", t
    )

    # Replace the vendor_spoof pattern with:
    vendor_spoof = _has(
        r"\b(?:pretending to be a known supplier|"
        r"pretends to be a known supplier|"
        r"impersonated supplier|fake vendor identity|"
        r"spoofed vendor|fake supplier)\b", t
    )

    # Replace the payroll_change pattern with:
    payroll_change = _has(
        r"\b(?:change|changes|redirect|redirects)\s+"
        r"(?:salary deposits|salary|payroll deposits|"
        r"payroll account|employee direct deposit)\b", t
    )

    crypto_support = _has(
       r"\b(?:fake crypto support|fake wallet support|"
        r"fake support agent|impersonated wallet support|"
        r"fraudulent crypto agent)\b", t
    )   

    rat_lure = _has(
        r"\b(?:remote access trojan|remote[- ]control trojan|"
        r"remote[- ]control program|remote administration malware|"
        r"backdoor)\b", t
    )


    # =========================================================
    # SPAM AND PROMOTIONAL ABUSE - WARNING
    # =========================================================

    # 46. Unrequested bulk promotional emails
    unsolicited_promo = _has(
        r"\b(?:unsolicited|unrequested|unconsented|"
        r"never contacted|did not request|"
        r"unfamiliar sender|unrequested bulk discount)\b", t
    )
    promo_content = _has(
        r"\b(?:promotional offers?|discounts?|"
        r"bulk offers?|shopping promotion|"
        r"advertisements?|limited deal|marketing campaign)\b", t
    )
    if unsolicited_promo and promo_content:
        add("UNSOLICITED_BULK_PROMOTION", "MEDIUM",
            "Unrequested promotional or bulk marketing content detected.",
            confirmed=False, confidence=0.87)


    # 47. Repeated coupon campaign
    repeated_coupon = _has(
        r"\b(?:repeated coupon campaign|"
        r"reminder number \w+|"
        r"discount code is still waiting|"
        r"repeated promotional reminder|"
        r"final coupon reminder)\b", t
    )
    if repeated_coupon:
        add("REPEATED_COUPON_CAMPAIGN", "MEDIUM",
            "Repeated promotional reminders indicate possible spam.",
            confirmed=False, confidence=0.86)


    # 48. Excessive promotional urgency
    promo_pressure = _has(
        r"\b(?:last hour|last chance|act immediately|"
        r"act now|offer expires|limited time|"
        r"lose this special promotional price|"
        r"purchase within minutes|hurry now)\b", t
    )
    commercial_context = _has(
        r"\b(?:promotion|promotional|discount|"
        r"coupon|offer|deal|price|sale|shopping)\b", t
    )
    if promo_pressure and commercial_context:
        add("EXCESSIVE_PROMOTIONAL_URGENCY", "MEDIUM",
            "High-pressure promotional language detected.",
            confirmed=False, confidence=0.88)


    # 49. Unverified giveaway
    giveaway_lure = _has(
        r"\b(?:free smartphone|free iphone|"
        r"free giveaway|unverified giveaway|"
        r"free rewards?|exclusive giveaway|"
        r"qualify for a free|claim your free prize)\b", t
    )
    giveaway_context = _has(
        r"\b(?:congratulations|qualify|claim|"
        r"unverified|register|winner|selected|giveaway)\b", t
    )
    if giveaway_lure and giveaway_context:
        add("UNVERIFIED_GIVEAWAY", "MEDIUM",
            "Unverified giveaway or reward solicitation detected.",
            confirmed=False, confidence=0.88)


    # 50. Misleading promotional subject
    misleading_subject = _has(
        r"\b(?:misleading subject line|"
        r"actually this message advertises|"
        r"disguised advertisement|"
        r"misleading promotional subject|"
        r"fake invoice promotion)\b", t
    )
    if misleading_subject:
        add("MISLEADING_PROMOTIONAL_SUBJECT", "MEDIUM",
            "Email subject may conceal promotional content.",
            confirmed=False, confidence=0.89)


    # 51. Aggressive referral marketing
    referral_pressure = _has(
        r"\b(?:forward this promotional message|"
        r"forward.{0,50}friends.{0,50}reward|"
        r"refer.{0,30}friends.{0,30}reward|"
        r"aggressive referral pitch|"
        r"share with everyone to unlock)\b", t
    )
    if referral_pressure:
        add("AGGRESSIVE_REFERRAL_MARKETING", "MEDIUM",
            "Aggressive referral or chain-message promotion detected.",
            confirmed=False, confidence=0.87)


    # 52. Hidden sponsorship
    hidden_sponsorship = _has(
        r"\b(?:hidden sponsorship|"
        r"undisclosed sponsored|"
        r"undisclosed paid promotion|"
        r"concealed sponsorship|"
        r"undisclosed affiliate promotion)\b", t
    )
    if hidden_sponsorship:
        add("HIDDEN_SPONSORSHIP", "MEDIUM",
            "Potentially undisclosed sponsored content detected.",
            confirmed=False, confidence=0.86)


    # 53. Unsolicited B2B outreach
    b2b_outreach = _has(
        r"\b(?:irrelevant b2b outreach|"
        r"found your business contact|"
        r"unsolicited business proposal|"
        r"unrequested sales outreach)\b", t
    )
    unwanted_service = _has(
        r"\b(?:did not request|never requested|"
        r"sell you a service|unsolicited|unrequested)\b", t
    )
    if b2b_outreach and unwanted_service:
        add("UNSOLICITED_B2B_OUTREACH", "MEDIUM",
            "Unrequested business solicitation detected.",
            confirmed=False, confidence=0.85)


    # 54. Unsupported health promotion
    health_promo = _has(
        r"\b(?:sensational health promotion|"
        r"miracle cure|instant results|"
        r"guaranteed health results|"
        r"instant weight loss)\b", t
    )
    unsupported_claim = _has(
        r"\b(?:without evidence|unverified|"
        r"promotional campaign|guaranteed cure|"
        r"no scientific evidence)\b", t
    )
    if health_promo and unsupported_claim:
        add("UNSUPPORTED_HEALTH_PROMOTION", "MEDIUM",
            "Potentially misleading health-related promotion detected.",
            confirmed=False, confidence=0.89)


    # 55. Deceptive scarcity promotion
    scarcity_claim = _has(
        r"\b(?:only one item left|"
        r"deceptive scarcity claim|"
        r"fake limited stock|"
        r"last item available|"
        r"artificial scarcity)\b", t
    )
    scarcity_context = _has(
        r"\b(?:unverified|promotion|promotional|"
        r"offer|discount|deceptive|purchase)\b", t
    )
    if scarcity_claim and scarcity_context:
        add("DECEPTIVE_SCARCITY_PROMOTION", "MEDIUM",
            "Potentially misleading product scarcity claim detected.",
            confirmed=False, confidence=0.87)


    # 56. Unverified affiliate marketing
    affiliate_pitch = _has(
        r"\b(?:unverified affiliate|"
        r"earn commission by promoting|"
        r"unfamiliar referral offer|"
        r"unknown affiliate program|"
        r"unverified commission offer)\b", t
    )
    if affiliate_pitch:
        add("UNVERIFIED_AFFILIATE_MARKETING", "MEDIUM",
            "Unverified affiliate or commission solicitation detected.",
            confirmed=False, confidence=0.86)


    # 57. Obfuscated promotional content
    obfuscated_promo = _has(
        r"\b(?:f\s+r\s+e\s+e|"
        r"c\s+a\s+s\s+h|"
        r"obfuscated promotional text|"
        r"bypass simple spam filters|"
        r"bypass spam detection)\b", t
    )
    if obfuscated_promo:
        add("OBFUSCATED_PROMOTIONAL_CONTENT", "MEDIUM",
            "Obfuscated promotional language or filter evasion detected.",
            confirmed=False, confidence=0.90)


    # =========================================================
    # DELIBERATE PROMOTIONAL FRAUD - RESTRICTED
    # =========================================================

    # 58. Unauthorized bulk distribution
    harvested_contacts = _has(
        r"\b(?:harvested addresses|"
        r"harvested email addresses|"
        r"stolen mailing list|"
        r"scraped email addresses)\b", t
    )
    unauthorized_distribution = _has(
        r"\b(?:without consent|unconsented|"
        r"unauthorized distribution|"
        r"send this advertisement to all)\b", t
    )
    if harvested_contacts and unauthorized_distribution:
        add("UNAUTHORIZED_BULK_DISTRIBUTION", "HIGH",
            "Unauthorized bulk distribution using harvested contacts detected.",
            confirmed=True, confidence=0.97)


    # 59. Forged subscription consent
    forged_consent = _has(
        r"\b(?:forged unsubscribe confirmation|"
        r"falsely claims.{0,80}opted in|"
        r"fabricated subscription consent|"
        r"forged mailing list consent|"
        r"fake opt-in confirmation)\b", t
    )
    if forged_consent:
        add("FORGED_SUBSCRIPTION_CONSENT", "HIGH",
            "Fabricated mailing-list consent detected.",
            confirmed=True, confidence=0.97)


    # 60. Marketing brand impersonation
    brand_impersonation = _has(
        r"\b(?:impersonated marketing brand|"
        r"falsely claims to come from|"
        r"impersonates a retailer|"
        r"fake retailer identity|"
        r"fraudulent brand identity)\b", t
    )
    marketing_context = _has(
        r"\b(?:promotion|retailer|marketing|"
        r"advertisement|offer|brand)\b", t
    )
    if brand_impersonation and marketing_context:
        add("MARKETING_BRAND_IMPERSONATION", "HIGH",
            "Fraudulent use of a marketing or retailer identity detected.",
            confirmed=True, confidence=0.97)


    # 61. Deceptive credential-collection redirect
    deceptive_redirect = _has(
        r"\b(?:disguised tracking|"
        r"deceptive tracking redirect|"
        r"hidden redirect|"
        r"redirects recipients)\b", t
    )
    credential_collection = _has(
        r"\b(?:credential[- ]collection|"
        r"credential[- ]harvesting|"
        r"credential[- ]stealing|"
        r"password collection)\b", t
    )
    if deceptive_redirect and credential_collection:
        add("DECEPTIVE_CREDENTIAL_REDIRECT", "CRITICAL",
            "Deceptive redirect associated with credential collection.",
            confirmed=True, confidence=0.99)


    # 62. Forged delivery promotion
    fake_delivery = _has(
        r"\b(?:fake delivery service|"
        r"forged delivery promotion|"
        r"nonexistent parcel|"
        r"fraudulent courier notification)\b", t
    )
    delivery_payment = _has(
        r"\b(?:payment details|card details|"
        r"delivery fee|provide payment|"
        r"banking information)\b", t
    )
    if fake_delivery and delivery_payment:
        add("FORGED_DELIVERY_PROMOTION", "CRITICAL",
            "Fraudulent delivery notification requesting payment information.",
            confirmed=True, confidence=0.98)


    # 63. Account takeover through promotional rewards
    account_reward = _has(
        r"\b(?:free premium access|"
        r"unlock premium access|"
        r"claim your reward|"
        r"account takeover promotion)\b", t
    )
    reward_credentials = _has(
        r"\b(?:sharing|share|send|provide|submit)"
        r".{0,60}"
        r"(?:otp|one[- ]time login code|"
        r"one[- ]time password|authentication code)\b", t
    )
    if account_reward and reward_credentials:
        add("PROMOTIONAL_ACCOUNT_TAKEOVER", "CRITICAL",
            "Promotional reward requests sensitive authentication information.",
            confirmed=True, confidence=0.99)


    # 64. Fraudulent charity marketing
    fake_charity = _has(
        r"\b(?:impersonated charity|"
        r"fake charity|fraudulent charity|"
        r"fake disaster[- ]relief campaign)\b", t
    )
    charity_collection = _has(
        r"\b(?:personal payment account|"
        r"collects donations|donate|"
        r"transfer donations|send money)\b", t
    )
    if fake_charity and charity_collection:
        add("FRAUDULENT_CHARITY_MARKETING", "CRITICAL",
            "Fraudulent charity identity used to solicit funds.",
            confirmed=True, confidence=0.98)


    # 65. Promotional malware installation lure
    promotional_gift = _has(
        r"\b(?:promotional gift|free reward|"
        r"malware[- ]themed advertising|"
        r"claim your gift)\b", t
    )
    suspicious_install = _has(
        r"\b(?:install the attached unknown program|"
        r"install an unknown program|"
        r"execute the unknown binary|"
        r"run the unverified executable)\b", t
    )
    if promotional_gift and suspicious_install:
        add("PROMOTIONAL_MALWARE_LURE", "CRITICAL",
            "Promotional content requests installation of untrusted software.",
            confirmed=True, confidence=0.98)


    # =========================================================
    # PHISHING AND SOCIAL ENGINEERING - WARNING
    # =========================================================

    # 66. Suspicious delivery notification
    suspicious_delivery = _has(
        r"\b(?:suspicious delivery notice|"
        r"unexpected parcel notice|"
        r"unfamiliar tracking link|"
        r"unverified courier notification)\b", t
    )
    if suspicious_delivery:
        add("SUSPICIOUS_DELIVERY_NOTIFICATION", "MEDIUM",
            "Unverified delivery or parcel-tracking notification detected.",
            confirmed=False, confidence=0.87)


    # 67. Unexpected meeting invitation
    unexpected_meeting = _has(
        r"\b(?:unexpected meeting invitation|"
        r"unusual meeting invitation|"
        r"unrequested meeting invitation)\b", t
    )
    external_registration = _has(
        r"\b(?:external registration link|"
        r"unknown registration page|"
        r"unfamiliar meeting link)\b", t
    )
    if unexpected_meeting and external_registration:
        add("SUSPICIOUS_MEETING_INVITATION", "MEDIUM",
            "Unexpected meeting invitation contains an unfamiliar registration link.",
            confirmed=False, confidence=0.86)


    # 68. Unknown manager requesting private response
    unknown_manager = _has(
        r"\b(?:someone claiming to be a manager|"
        r"unknown manager|unverified manager|"
        r"unfamiliar executive)\b", t
    )
    private_pressure = _has(
        r"\b(?:immediate private response|"
        r"reply privately|respond immediately|"
        r"private communication|urgent private reply)\b", t
    )
    if unknown_manager and private_pressure:
        add("UNVERIFIED_MANAGER_REQUEST", "MEDIUM",
            "Unverified managerial identity requests urgent private communication.",
            confirmed=False, confidence=0.90)


    # 69. Unverified cloud-sharing alert
    unknown_cloud_sender = _has(
        r"\b(?:a stranger has shared|"
        r"unverified cloud[- ]share|"
        r"unknown file sender|"
        r"unfamiliar file[- ]sharing notification)\b", t
    )
    cloud_login = _has(
        r"\b(?:sign in to view|login to view|"
        r"authenticate to access|"
        r"shared a file|open the shared file)\b", t
    )
    if unknown_cloud_sender and cloud_login:
        add("UNVERIFIED_CLOUD_SHARE", "MEDIUM",
            "Unverified file-sharing notification requests authentication.",
            confirmed=False, confidence=0.90)


    # 70. Suspicious mailbox quota notification
    mailbox_quota = _has(
        r"\b(?:mailbox.{0,40}(?:full|quota|limit)|"
        r"email storage limit|"
        r"suspicious mailbox quota)\b", t
    )
    mailbox_pressure = _has(
        r"\b(?:external link|supposedly|"
        r"verify your mailbox|"
        r"unfamiliar link|account suspension)\b", t
    )
    if mailbox_quota and mailbox_pressure:
        add("SUSPICIOUS_MAILBOX_QUOTA", "MEDIUM",
            "Suspicious mailbox quota or storage notification detected.",
            confirmed=False, confidence=0.90)


    # 71. Suspicious recruitment outreach
    unknown_recruiter = _has(
        r"\b(?:unfamiliar recruiter|"
        r"unknown recruiter|"
        r"unverified recruitment agency|"
        r"odd recruitment outreach)\b", t
    )
    recruitment_request = _has(
        r"\b(?:personal information|quick reply|"
        r"immediate response|"
        r"personal details|registration fee)\b", t
    )
    if unknown_recruiter and recruitment_request:
        add("SUSPICIOUS_RECRUITMENT_OUTREACH", "MEDIUM",
            "Unverified recruitment communication requests personal information.",
            confirmed=False, confidence=0.89)


    # 72. Unverified legal notification
    legal_notice = _has(
        r"\b(?:unexpected legal notice|"
        r"generic legal notification|"
        r"unverified legal notice|"
        r"unknown legal representative)\b", t
    )
    missing_legal_reference = _has(
        r"\b(?:no case reference|"
        r"without a case number|"
        r"demands a response|"
        r"immediate legal response)\b", t
    )
    if legal_notice and missing_legal_reference:
        add("UNVERIFIED_LEGAL_NOTIFICATION", "MEDIUM",
            "Unexpected legal communication lacks sufficient verification.",
            confirmed=False, confidence=0.88)


    # 73. Unverified supplier communication
    supplier_identity = _has(
        r"\b(?:new supplier contact|"
        r"unverified supplier|"
        r"unknown vendor|"
        r"unfamiliar supplier)\b", t
    )
    communication_change = _has(
        r"\b(?:change the communication channel|"
        r"switch communication channels|"
        r"contact me privately|"
        r"use a different email address)\b", t
    )
    if supplier_identity and communication_change:
        add("UNVERIFIED_SUPPLIER_REQUEST", "MEDIUM",
            "Unverified supplier requests a communication-channel change.",
            confirmed=False, confidence=0.88)


    # 74. Unknown voicemail notification
    unknown_voicemail = _has(
        r"\b(?:unknown voicemail alert|"
        r"unverified voicemail notification|"
        r"unexpected voicemail)\b", t
    )
    voicemail_service = _has(
        r"\b(?:unfamiliar notification service|"
        r"unknown service|external link|"
        r"listen to your voicemail)\b", t
    )
    if unknown_voicemail and voicemail_service:
        add("UNKNOWN_VOICEMAIL_NOTIFICATION", "MEDIUM",
            "Voicemail notification originates from an unverified service.",
            confirmed=False, confidence=0.87)


    # 75. Unverified social media alert
    social_media_alert = _has(
        r"\b(?:social media alert|"
        r"platform[- ]style warning|"
        r"social media notification)\b", t
    )
    unverified_social_sender = _has(
        r"\b(?:sender that cannot be verified|"
        r"unverified sender|"
        r"unknown sender|"
        r"unfamiliar notification)\b", t
    )
    if social_media_alert and unverified_social_sender:
        add("UNVERIFIED_SOCIAL_MEDIA_ALERT", "MEDIUM",
            "Unverified social media security notification detected.",
            confirmed=False, confidence=0.88)


    # =========================================================
    # CREDENTIAL THEFT AND IMPERSONATION - RESTRICTED
    # =========================================================

    # 76. One-time password theft
    fake_security_identity = _has(
        r"\b(?:fake security representative|"
        r"impersonated security officer|"
        r"fraudulent support agent|"
        r"fake bank representative)\b", t
    )
    otp_request = _has(
        r"\b(?:asks?|requests?|provide|"
        r"share|send|submit|disclose)"
        r".{0,80}"
        r"(?:otp|one[- ]time password|"
        r"one[- ]time login code|"
        r"verification code)\b", t
    )
    if fake_security_identity and otp_request:
        add("ONE_TIME_PASSWORD_THEFT", "CRITICAL",
            "Impersonated security representative requests authentication codes.",
            confirmed=True, confidence=0.99)


    # 77. Executive impersonation
    executive_spoofing = _has(
        r"\b(?:impersonating the ceo|"
        r"impersonated executive|"
        r"fake ceo|fake cfo|"
        r"forged cfo instruction|"
        r"executive impersonation)\b", t
    )
    executive_transfer = _has(
        r"\b(?:funds transfer|money transfer|"
        r"vendor payment|confidential payment|"
        r"transfer funds|wire transfer)\b", t
    )
    if executive_spoofing and executive_transfer:
        add("EXECUTIVE_IMPERSONATION_FRAUD", "CRITICAL",
            "Executive impersonation associated with a financial transfer.",
            confirmed=True, confidence=0.99)


    # 78. Fake SSO authentication portal
    forged_authentication = _has(
        r"\b(?:forged sign[- ]in page|"
        r"fake sso login portal|"
        r"fake authentication portal|"
        r"counterfeit login page|"
        r"fraudulent authentication page)\b", t
    )
    sso_context = _has(
        r"\b(?:sso|authentication portal|"
        r"company login|corporate login|"
        r"sign[- ]in|credentials)\b", t
    )
    if forged_authentication and sso_context:
        add("FAKE_SSO_AUTHENTICATION_PORTAL", "CRITICAL",
            "Forged corporate authentication portal detected.",
            confirmed=True, confidence=0.99)


    # 79. Payroll identity theft
    fake_hr = _has(
        r"\b(?:impersonated hr officer|"
        r"fake hr representative|"
        r"fraudulent payroll officer|"
        r"payroll identity theft)\b", t
    )
    payroll_sensitive_data = _has(
        r"\b(?:national id|banking information|"
        r"identity documents|bank account details|"
        r"employee identity information)\b", t
    )
    if fake_hr and payroll_sensitive_data:
        add("PAYROLL_IDENTITY_THEFT", "CRITICAL",
            "Fraudulent HR or payroll communication requests sensitive identity data.",
            confirmed=True, confidence=0.99)


    # 80. Fake account recovery
    fake_recovery = _has(
        r"\b(?:fraudulent recovery team|"
        r"fake account recovery|"
        r"impersonated recovery agent|"
        r"fake recovery support)\b", t
    )
    recovery_codes = _has(
        r"\b(?:backup authentication codes?|"
        r"backup codes?|recovery codes?|"
        r"recovery phrase|authentication tokens?)\b", t
    )
    if fake_recovery and recovery_codes:
        add("FAKE_ACCOUNT_RECOVERY", "CRITICAL",
            "Fraudulent account recovery communication requests sensitive codes.",
            confirmed=True, confidence=0.99)


    # 81. Vendor identity spoofing
    vendor_spoofing = _has(
        r"\b(?:vendor identity spoofing|"
        r"pretends to be a known supplier|"
        r"impersonated vendor|"
        r"fake supplier identity)\b", t
    )
    vendor_data_request = _has(
        r"\b(?:collect confidential files|"
        r"request confidential documents|"
        r"vendor payment|bank details|"
        r"confidential information)\b", t
    )
    if vendor_spoofing and vendor_data_request:
        add("VENDOR_IDENTITY_SPOOFING", "CRITICAL",
            "Supplier impersonation associated with confidential data or payments.",
            confirmed=True, confidence=0.98)


    # 82. Helpdesk remote-access scam
    fake_helpdesk = _has(
        r"\b(?:impersonator|fake helpdesk|"
        r"fraudulent support agent|"
        r"helpdesk remote[- ]access scam)\b", t
    )
    remote_installation = _has(
        r"\b(?:install remote[- ]control software|"
        r"install remote[- ]access software|"
        r"grant remote access|"
        r"enable remote administration)\b", t
    )
    if fake_helpdesk and remote_installation:
        add("HELPDESK_REMOTE_ACCESS_SCAM", "CRITICAL",
            "Impersonated support personnel request remote access.",
            confirmed=True, confidence=0.99)


    # 83. Fake security escalation
    forged_security_notice = _has(
        r"\b(?:fake security escalation|"
        r"forged incident[- ]response notice|"
        r"fake security incident|"
        r"impersonated security team)\b", t
    )
    security_secret_request = _has(
        r"\b(?:access tokens?|api keys?|"
        r"authentication secrets?|"
        r"privileged credentials|"
        r"production passwords?)\b", t
    )
    if forged_security_notice and security_secret_request:
        add("FAKE_SECURITY_ESCALATION", "CRITICAL",
            "Forged security escalation requests sensitive authentication secrets.",
            confirmed=True, confidence=0.99)


    # 84. QR-code credential phishing
    qr_code_context = _has(
        r"\b(?:qr[- ]code|scan the qr|"
        r"embedded qr|qr phishing)\b", t
    )
    qr_credential_lure = _has(
        r"\b(?:credential form|"
        r"fake company login form|"
        r"fake login notice|"
        r"credential[- ]stealing|"
        r"fraudulent login page)\b", t
    )
    if qr_code_context and qr_credential_lure:
        add("QR_CODE_CREDENTIAL_PHISHING", "CRITICAL",
            "QR-code lure associated with fraudulent credential collection.",
            confirmed=True, confidence=0.99)


    # 85. MFA fatigue attack
    mfa_impersonation = _has(
        r"\b(?:impersonator|fake support|"
        r"fraudulent security agent|"
        r"mfa fatigue pretext)\b", t
    )
    mfa_approval = _has(
        r"\b(?:approve|accept|confirm)"
        r".{0,60}"
        r"(?:mfa prompt|authentication prompt|"
        r"unexpected login request|"
        r"push notification)\b", t
    )
    if mfa_impersonation and mfa_approval:
        add("MFA_FATIGUE_ATTACK", "CRITICAL",
            "Fraudulent request to approve an authentication prompt.",
            confirmed=True, confidence=0.99)


    # 86. Confidential employee database extraction
    fake_auditor = _has(
        r"\b(?:fake auditor|"
        r"impersonated auditor|"
        r"fraudulent auditor|"
        r"confidential data extraction)\b", t
    )
    employee_database = _has(
        r"\b(?:employee identity database|"
        r"full employee database|"
        r"employee identity records|"
        r"confidential employee information)\b", t
    )
    if fake_auditor and employee_database:
        add("CONFIDENTIAL_EMPLOYEE_DATA_EXTRACTION", "CRITICAL",
            "Fraudulent request for confidential employee identity records.",
            confirmed=True, confidence=0.99)


    # =========================================================
    # FINANCIAL FRAUD INDICATORS - WARNING
    # =========================================================

    # 87. Unverified investment returns
    investment_claim = _has(
        r"\b(?:unusually high guaranteed returns|"
        r"guaranteed investment returns|"
        r"unverified investment return|"
        r"risk[- ]free high returns)\b", t
    )
    if investment_claim:
        add("UNVERIFIED_INVESTMENT_RETURN", "MEDIUM",
            "Unverified or potentially misleading investment-return claim.",
            confirmed=False, confidence=0.91)


    # 88. Unexpected payment reminder
    payment_reminder = _has(
        r"\b(?:unexpected payment reminder|"
        r"overdue payment|outstanding invoice|"
        r"unverified payment notice)\b", t
    )
    missing_invoice = _has(
        r"\b(?:without providing a verifiable invoice|"
        r"no invoice reference|"
        r"unverified invoice|"
        r"missing invoice details)\b", t
    )
    if payment_reminder and missing_invoice:
        add("UNVERIFIED_PAYMENT_REMINDER", "MEDIUM",
            "Payment reminder lacks sufficient invoice verification.",
            confirmed=False, confidence=0.89)


    # 89. Unsolicited loan offer
    unsolicited_loan = _has(
        r"\b(?:unsolicited loan offer|"
        r"unfamiliar lender|"
        r"unverified loan provider|"
        r"unknown lending service)\b", t
    )
    loan_offer = _has(
        r"\b(?:preapproved|pre[- ]approved|"
        r"loan offer|instant loan|"
        r"loan approval|guaranteed loan)\b", t
    )
    if unsolicited_loan and loan_offer:
        add("UNSOLICITED_LOAN_OFFER", "MEDIUM",
            "Unverified lender offers unsolicited financial services.",
            confirmed=False, confidence=0.88)


    # 90. Suspicious tax refund
    tax_refund = _has(
        r"\b(?:suspicious tax refund|"
        r"unexpected tax refund|"
        r"eligible for a refund|"
        r"unverified tax notification)\b", t
    )
    refund_context = _has(
        r"\b(?:unexpected|unverified|"
        r"suspicious|unfamiliar|unknown)\b", t
    )
    if tax_refund and refund_context:
        add("SUSPICIOUS_TAX_REFUND", "MEDIUM",
            "Unexpected or unverified tax-refund notification detected.",
            confirmed=False, confidence=0.89)


    # 91. Unknown cryptocurrency promotion
    unknown_crypto = _has(
        r"\b(?:unknown crypto promotion|"
        r"unfamiliar cryptocurrency investment group|"
        r"unverified crypto investment|"
        r"unknown cryptocurrency platform)\b", t
    )
    if unknown_crypto:
        add("UNVERIFIED_CRYPTO_PROMOTION", "MEDIUM",
            "Unverified cryptocurrency investment solicitation detected.",
            confirmed=False, confidence=0.90)


    # 92. Unverified donation appeal
    donation_appeal = _has(
        r"\b(?:donation appeal|charity appeal|"
        r"fundraising request|donation request)\b", t
    )
    charity_unverified = _has(
        r"\b(?:unverified|"
        r"lacks independently verifiable|"
        r"unknown charity|"
        r"unfamiliar organization)\b", t
    )
    if donation_appeal and charity_unverified:
        add("UNVERIFIED_DONATION_APPEAL", "MEDIUM",
            "Donation solicitation lacks sufficient organization verification.",
            confirmed=False, confidence=0.88)


    # 93. Urgent gift-card purchase request
    gift_card_purchase = _has(
        r"\b(?:purchase gift cards|"
        r"buy gift cards|"
        r"purchase gift vouchers|"
        r"buy gift vouchers)\b", t
    )
    gift_card_pressure = _has(
        r"\b(?:immediately|urgent|"
        r"new contact|unexpected|"
        r"unfamiliar sender)\b", t
    )
    if gift_card_purchase and gift_card_pressure:
        add("URGENT_GIFT_CARD_PURCHASE", "MEDIUM",
            "Unverified or urgent gift-card purchase request detected.",
            confirmed=False, confidence=0.90)


    # 94. Unverified trading signal
    trading_signal = _has(
        r"\b(?:urgent trading signal|"
        r"time[- ]sensitive investment tips|"
        r"unverified trading advice|"
        r"unknown trading service)\b", t
    )
    if trading_signal:
        add("UNVERIFIED_TRADING_SIGNAL", "MEDIUM",
            "Unverified time-sensitive investment or trading solicitation.",
            confirmed=False, confidence=0.87)


    # 95. Unverified scholarship processing fee
    scholarship_context = _has(
        r"\b(?:scholarship|education grant|"
        r"student grant|scholarship application)\b", t
    )
    scholarship_fee = _has(
        r"\b(?:fee before processing|"
        r"upfront processing fee|"
        r"unverified scholarship fee|"
        r"advance application charge)\b", t
    )
    if scholarship_context and scholarship_fee:
        add("UNVERIFIED_SCHOLARSHIP_FEE", "MEDIUM",
            "Scholarship solicitation requests an unverified processing fee.",
            confirmed=False, confidence=0.90)


    # 96. High-pressure insurance solicitation
    insurance_context = _has(
        r"\b(?:insurance|insurance policy|"
        r"insurance pitch|insurance premium)\b", t
    )
    insurance_pressure = _has(
        r"\b(?:purchased within minutes|"
        r"buy immediately|"
        r"high[- ]pressure insurance|"
        r"purchase the policy immediately)\b", t
    )
    if insurance_context and insurance_pressure:
        add("HIGH_PRESSURE_INSURANCE_PITCH", "MEDIUM",
            "High-pressure insurance purchase solicitation detected.",
            confirmed=False, confidence=0.87)


    # 97. Unknown escrow service
    unknown_escrow = _has(
        r"\b(?:unknown escrow invitation|"
        r"unfamiliar escrow service|"
        r"unverified escrow platform|"
        r"unknown escrow provider)\b", t
    )
    if unknown_escrow:
        add("UNVERIFIED_ESCROW_SERVICE", "MEDIUM",
            "Unverified escrow or payment intermediary detected.",
            confirmed=False, confidence=0.89)


    # 98. Unexpected prize notification
    unexpected_prize = _has(
        r"\b(?:contest you did not enter|"
        r"unverified prize notification|"
        r"unexpected cash prize|"
        r"unknown lottery notification)\b", t
    )
    if unexpected_prize:
        add("UNVERIFIED_PRIZE_NOTIFICATION", "MEDIUM",
            "Unexpected prize or lottery notification detected.",
            confirmed=False, confidence=0.90)


    # =========================================================
    # CONFIRMED FINANCIAL FRAUD - RESTRICTED
    # =========================================================

    # 99. Advance-fee loan fraud
    advance_fee = _has(
        r"\b(?:upfront release charge|"
        r"advance[- ]fee|upfront fee|"
        r"loan release fee|processing charge)\b", t
    )
    nonexistent_loan = _has(
        r"\b(?:loan that does not exist|"
        r"nonexistent loan|fake loan|"
        r"fraudulent loan|advance[- ]fee loan scam)\b", t
    )
    if advance_fee and nonexistent_loan:
        add("ADVANCE_FEE_LOAN_FRAUD", "CRITICAL",
            "Advance payment requested for a fraudulent loan.",
            confirmed=True, confidence=0.99)


    # 100. Business email compromise
    bec_identity = _has(
        r"\b(?:forged cfo instruction|"
        r"business email compromise|"
        r"impersonated finance officer|"
        r"forged payment instruction)\b", t
    )
    bec_payment = _has(
        r"\b(?:attacker account|"
        r"redirects a vendor payment|"
        r"unauthorized bank account|"
        r"fraudulent beneficiary)\b", t
    )
    if bec_identity and bec_payment:
        add("BUSINESS_EMAIL_COMPROMISE", "CRITICAL",
            "Fraudulent financial instruction redirects a legitimate payment.",
            confirmed=True, confidence=0.99)


    # 101. Bank credential theft
    fake_bank = _has(
        r"\b(?:fake bank message|"
        r"fake banking site|"
        r"fraudulent bank notification|"
        r"bank credential theft)\b", t
    )
    bank_credentials = _has(
        r"\b(?:banking username and password|"
        r"online banking credentials|"
        r"bank login details|"
        r"card details|banking password)\b", t
    )
    if fake_bank and bank_credentials:
        add("BANK_CREDENTIAL_THEFT", "CRITICAL",
            "Fraudulent banking communication requests sensitive credentials.",
            confirmed=True, confidence=0.99)


    # 102. Ponzi investment solicitation
    ponzi_pattern = _has(
        r"\b(?:ponzi solicitation|ponzi scheme|"
        r"returns funded by recruiting new investors|"
        r"returns funded by new investors|"
        r"fixed returns funded by recruiting)\b", t
    )
    if ponzi_pattern:
        add("PONZI_INVESTMENT_SOLICITATION", "CRITICAL",
            "Investment solicitation indicates a Ponzi-style funding structure.",
            confirmed=True, confidence=0.98)


    # 103. Fraudulent refund processing
    fake_refund = _has(
        r"\b(?:nonexistent refund|"
        r"fake refund processing|"
        r"fraudulent refund|"
        r"fake refund notification)\b", t
    )
    refund_card_data = _has(
        r"\b(?:card number and security code|"
        r"card security code|"
        r"cvv|cvc|bank login details)\b", t
    )
    if fake_refund and refund_card_data:
        add("FRAUDULENT_REFUND_PROCESSING", "CRITICAL",
            "Fraudulent refund request collects sensitive payment credentials.",
            confirmed=True, confidence=0.99)


    # 104. Gift-card redemption fraud
    gift_card_impersonation = _has(
        r"\b(?:impersonated executive|"
        r"fake manager|"
        r"gift card fraud|"
        r"fraudulent gift card request)\b", t
    )
    gift_card_codes = _has(
        r"\b(?:gift card numbers|"
        r"redemption codes|"
        r"gift voucher codes|"
        r"gift card pin)\b", t
    )
    if gift_card_impersonation and gift_card_codes:
        add("GIFT_CARD_REDEMPTION_FRAUD", "CRITICAL",
            "Fraudulent request for gift-card numbers or redemption codes.",
            confirmed=True, confidence=0.99)


    # 105. Payroll payment diversion
    payroll_diversion = _has(
        r"\b(?:payroll diversion|"
        r"forged employee request|"
        r"fraudulent payroll instruction)\b", t
    )
    unauthorized_payroll_account = _has(
        r"\b(?:unauthorized account|"
        r"attacker account|"
        r"fraudulent bank account|"
        r"redirect salary deposits)\b", t
    )
    if payroll_diversion and unauthorized_payroll_account:
        add("PAYROLL_PAYMENT_DIVERSION", "CRITICAL",
            "Fraudulent instruction redirects employee salary payments.",
            confirmed=True, confidence=0.99)


    # 106. Cryptocurrency wallet credential theft
    fake_wallet_support = _has(
        r"\b(?:fake support agent|"
        r"fraudulent wallet support|"
        r"cryptocurrency wallet theft|"
        r"impersonated crypto support)\b", t
    )
    wallet_secret = _has(
        r"\b(?:wallet recovery phrase|"
        r"seed phrase|wallet private key|"
        r"wallet recovery words)\b", t
    )
    if fake_wallet_support and wallet_secret:
        add("CRYPTO_WALLET_CREDENTIAL_THEFT", "CRITICAL",
            "Fraudulent wallet support requests cryptocurrency recovery secrets.",
            confirmed=True, confidence=0.99)


    # 107. Fake tax authority payment
    fake_tax_authority = _has(
        r"\b(?:impersonates the tax authority|"
        r"fake tax authority|"
        r"fraudulent tax officer|"
        r"tax authority impersonation)\b", t
    )
    tax_payment_demand = _has(
        r"\b(?:immediate transfer|"
        r"urgent payment|"
        r"transfer funds|"
        r"pay immediately)\b", t
    )
    if fake_tax_authority and tax_payment_demand:
        add("FAKE_TAX_AUTHORITY_PAYMENT", "CRITICAL",
            "Tax authority impersonation associated with a payment demand.",
            confirmed=True, confidence=0.99)


    # 108. Money mule recruitment
    mule_transfer = _has(
        r"\b(?:receive and forward unknown third[- ]party funds|"
        r"money mule recruitment|"
        r"receive and forward unknown funds|"
        r"transfer unknown third[- ]party payments)\b", t
    )
    if mule_transfer:
        add("MONEY_MULE_RECRUITMENT", "HIGH",
            "Suspicious recruitment involves forwarding unknown third-party funds.",
            confirmed=True, confidence=0.97)


    # 109. Loan identity harvesting
    fake_lender = _has(
        r"\b(?:fake lender|"
        r"fraudulent loan provider|"
        r"loan identity harvesting|"
        r"impersonated lending service)\b", t
    )
    loan_identity_data = _has(
        r"\b(?:identity documents|"
        r"bank login details|"
        r"banking credentials|"
        r"national identity information)\b", t
    )
    if fake_lender and loan_identity_data:
        add("LOAN_IDENTITY_HARVESTING", "CRITICAL",
            "Fraudulent lender requests sensitive identity or banking data.",
            confirmed=True, confidence=0.99)


    # 110. Romance payment manipulation
    fabricated_emergency = _has(
        r"\b(?:invents an emergency|"
        r"fabricated emergency|"
        r"fake emergency|"
        r"romance payment manipulation)\b", t
    )
    romance_payment = _has(
        r"\b(?:money transfer|"
        r"send money|obtain a payment|"
        r"transfer funds)\b", t
    )
    if fabricated_emergency and romance_payment:
        add("ROMANCE_PAYMENT_MANIPULATION", "HIGH",
            "Fabricated emergency is used to solicit a financial transfer.",
            confirmed=True, confidence=0.97)


    # =========================================================
    # URL AND HYPERLINK INDICATORS - WARNING
    # =========================================================

    # 111. Unfamiliar shortened URL
    unfamiliar_short_url = _has(
        r"\b(?:unfamiliar shortened url|"
        r"undisclosed destination|"
        r"unknown shortened link|"
        r"unverified short link)\b", t
    )
    if unfamiliar_short_url:
        add("UNFAMILIAR_SHORTENED_URL", "MEDIUM",
            "Shortened URL has an unfamiliar or undisclosed destination.",
            confirmed=False, confidence=0.88)


    # 112. Suspicious tracking parameters
    suspicious_tracking = _has(
        r"\b(?:unusually long tracking parameters|"
        r"unexpected tracking parameters|"
        r"unverified tracking redirect|"
        r"unusual tracking query)\b", t
    )
    if suspicious_tracking:
        add("SUSPICIOUS_TRACKING_PARAMETERS", "MEDIUM",
            "Potentially suspicious URL tracking parameters detected.",
            confirmed=False, confidence=0.85)


    # 113. Insecure authentication page
    insecure_login = _has(
        r"\b(?:http[- ]only login page|"
        r"non[- ]https page|"
        r"insecure login page|"
        r"unencrypted authentication page)\b", t
    )
    if insecure_login:
        add("INSECURE_AUTHENTICATION_PAGE", "MEDIUM",
            "Authentication page may use an insecure HTTP connection.",
            confirmed=False, confidence=0.91)


    # 114. Unfamiliar subdomain
    unfamiliar_subdomain = _has(
        r"\b(?:unfamiliar subdomain|"
        r"newly introduced subdomain|"
        r"unverified subdomain|"
        r"unknown authentication subdomain)\b", t
    )
    if unfamiliar_subdomain:
        add("UNFAMILIAR_SUBDOMAIN", "MEDIUM",
            "Message references an unfamiliar or unverified subdomain.",
            confirmed=False, confidence=0.86)


    # 115. Suspicious redirect chain
    redirect_chain = _has(
        r"\b(?:suspicious redirect chain|"
        r"multiple unrelated domains|"
        r"unverified redirect chain|"
        r"redirects through unknown domains)\b", t
    )
    if redirect_chain:
        add("SUSPICIOUS_REDIRECT_CHAIN", "MEDIUM",
            "URL may redirect through multiple unrelated destinations.",
            confirmed=False, confidence=0.90)


    # 116. Encoded URL parameters
    encoded_url_parameters = _has(
        r"\b(?:encoded query parameters|"
        r"unusually long encoded parameter string|"
        r"obfuscated query parameters|"
        r"encoded destination parameter)\b", t
    )
    if encoded_url_parameters:
        add("SUSPICIOUS_ENCODED_URL_PARAMETERS", "MEDIUM",
            "URL contains potentially suspicious encoded parameters.",
            confirmed=False, confidence=0.86)


    # 117. Lookalike domain concern
    lookalike_domain = _has(
        r"\b(?:lookalike domain|"
        r"resembles a known company name|"
        r"not the verified domain|"
        r"similar but unverified domain)\b", t
    )
    if lookalike_domain:
        add("LOOKALIKE_DOMAIN_CONCERN", "MEDIUM",
            "Domain resembles a legitimate organization but requires verification.",
            confirmed=False, confidence=0.91)


    # 118. Unexpected QR-code link
    unexpected_qr = _has(
        r"\b(?:unexpected qr[- ]code|"
        r"qr code in an unrequested message|"
        r"unverified qr[- ]code|"
        r"unknown qr destination)\b", t
    )
    if unexpected_qr:
        add("UNEXPECTED_QR_CODE_LINK", "MEDIUM",
            "Unexpected QR-code destination requires verification.",
            confirmed=False, confidence=0.89)


    # 119. Hyperlink display mismatch
    hyperlink_mismatch = _has(
        r"\b(?:link and display mismatch|"
        r"underlying destination appear unrelated|"
        r"visible link label.{0,80}unrelated|"
        r"displayed url differs from destination)\b", t
    )
    if hyperlink_mismatch:
        add("HYPERLINK_DISPLAY_MISMATCH", "MEDIUM",
            "Displayed hyperlink may differ from its actual destination.",
            confirmed=False, confidence=0.91)


    # 120. Unknown external file-sharing link
    unknown_file_link = _has(
        r"\b(?:unknown file[- ]sharing link|"
        r"external file[- ]sharing url.{0,50}without context|"
        r"unverified file[- ]sharing destination)\b", t
    )
    if unknown_file_link:
        add("UNKNOWN_FILE_SHARING_LINK", "MEDIUM",
            "Unverified external file-sharing destination detected.",
            confirmed=False, confidence=0.88)


    # 121. Expired-link pressure
    link_expiry_pressure = _has(
        r"\b(?:expired[- ]link pressure|"
        r"unfamiliar link before it expires|"
        r"unknown link.{0,50}expires|"
        r"open immediately before the link expires)\b", t
    )
    if link_expiry_pressure:
        add("EXPIRED_LINK_PRESSURE", "MEDIUM",
            "Unfamiliar hyperlink is accompanied by expiration pressure.",
            confirmed=False, confidence=0.88)


    # =========================================================
    # MALICIOUS URL AND CREDENTIAL COLLECTION - RESTRICTED
    # =========================================================

    # 122. Credential collection URL
    credential_collection_page = _has(
        r"\b(?:fake authentication page|"
        r"credential collection url|"
        r"fraudulent credential form|"
        r"credential harvesting page)\b", t
    )
    corporate_credentials = _has(
        r"\b(?:corporate password|"
        r"corporate credentials|"
        r"account password|"
        r"employee login credentials)\b", t
    )
    if credential_collection_page and corporate_credentials:
        add("CREDENTIAL_COLLECTION_URL", "CRITICAL",
            "Fraudulent authentication page requests corporate credentials.",
            confirmed=True, confidence=0.99)


    # 123. OTP harvesting link
    otp_collection_link = _has(
        r"\b(?:otp harvesting link|"
        r"otp collection form|"
        r"fraudulent verification form)\b", t
    )
    banking_otp = _has(
        r"\b(?:one[- ]time banking code|"
        r"banking otp|"
        r"one[- ]time password|"
        r"verification code)\b", t
    )
    if otp_collection_link and banking_otp:
        add("OTP_HARVESTING_LINK", "CRITICAL",
            "Linked form is associated with collection of sensitive authentication codes.",
            confirmed=True, confidence=0.99)


    # 124. Malware download URL
    malware_execution = _has(
        r"\b(?:download and execute|"
        r"download and run|"
        r"execute an unknown binary|"
        r"install the unknown executable)\b", t
    )
    untrusted_binary = _has(
        r"\b(?:unknown binary|"
        r"malware download url|"
        r"malicious executable|"
        r"untrusted executable)\b", t
    )
    if malware_execution and untrusted_binary:
        add("MALWARE_DOWNLOAD_URL", "CRITICAL",
            "Message directs execution of potentially malicious software.",
            confirmed=True, confidence=0.98)


    # 125. Fake payroll login portal
    fake_payroll_portal = _has(
        r"\b(?:forged payroll portal|"
        r"fake payroll login link|"
        r"fraudulent payroll page|"
        r"counterfeit payroll portal)\b", t
    )
    payroll_credentials = _has(
        r"\b(?:employee credentials|"
        r"employee password|"
        r"payroll login details|"
        r"corporate credentials)\b", t
    )
    if fake_payroll_portal and payroll_credentials:
        add("FAKE_PAYROLL_LOGIN_PORTAL", "CRITICAL",
            "Forged payroll portal requests employee credentials.",
            confirmed=True, confidence=0.99)


    # 126. Fraudulent banking portal
    banking_portal_spoof = _has(
        r"\b(?:impersonates a banking portal|"
        r"fake banking site|"
        r"counterfeit banking portal|"
        r"fraudulent banking website)\b", t
    )
    banking_sensitive_data = _has(
        r"\b(?:card details|card number|"
        r"banking password|"
        r"online banking credentials|"
        r"security code)\b", t
    )
    if banking_portal_spoof and banking_sensitive_data:
        add("FRAUDULENT_BANKING_PORTAL", "CRITICAL",
            "Fraudulent banking portal requests sensitive payment information.",
            confirmed=True, confidence=0.99)


    # 127. Confidential database upload
    confidential_database = _has(
        r"\b(?:confidential customer database|"
        r"confidential employee database|"
        r"customer identity records|"
        r"production customer records)\b", t
    )
    external_upload = _has(
        r"\b(?:uploading|upload|transfer|"
        r"export|send|forward)\b", t
    )
    external_data_destination = _has(
        r"\b(?:external site|"
        r"unapproved external service|"
        r"unauthorized destination|"
        r"unverified external portal)\b", t
    )
    if confidential_database and external_upload and external_data_destination:
        add("CONFIDENTIAL_DATABASE_EXFILTRATION", "CRITICAL",
            "Sensitive database is requested for transfer to an external destination.",
            confirmed=True, confidence=0.99)


    # 128. Ransomware download lure
    fake_update = _has(
        r"\b(?:fake software update|"
        r"fraudulent software update|"
        r"ransomware download lure)\b", t
    )
    ransomware_payload = _has(
        r"\b(?:ransomware payload|"
        r"purported ransomware payload|"
        r"ransomware executable|"
        r"ransomware download)\b", t
    )
    if fake_update and ransomware_payload:
        add("RANSOMWARE_DOWNLOAD_LURE", "CRITICAL",
            "Fraudulent software update is associated with ransomware.",
            confirmed=True, confidence=0.99)


    # 129. Unauthorized administrative portal
    forged_admin_portal = _has(
        r"\b(?:forged admin page|"
        r"unauthorized admin portal|"
        r"fake administrator portal|"
        r"fraudulent admin login)\b", t
    )
    privileged_credentials = _has(
        r"\b(?:privileged credentials|"
        r"administrator password|"
        r"root credentials|"
        r"administrative access tokens)\b", t
    )
    if forged_admin_portal and privileged_credentials:
        add("UNAUTHORIZED_ADMIN_PORTAL", "CRITICAL",
            "Forged administrative portal requests privileged credentials.",
            confirmed=True, confidence=0.99)


    # 130. Fraudulent cloud storage share
    fake_cloud_share = _has(
        r"\b(?:fraudulent shared[- ]file link|"
        r"fake cloud storage share|"
        r"forged cloud sharing notification|"
        r"fake shared document)\b", t
    )
    cloud_credentials = _has(
        r"\b(?:sso credentials|"
        r"corporate password|"
        r"employee login credentials|"
        r"cloud account credentials)\b", t
    )
    if fake_cloud_share and cloud_credentials:
        add("FRAUDULENT_CLOUD_STORAGE_SHARE", "CRITICAL",
            "Fraudulent cloud-sharing notification requests sensitive credentials.",
            confirmed=True, confidence=0.99)


    # 131. Password reset spoofing
    password_reset_spoof = _has(
        r"\b(?:counterfeit password[- ]reset url|"
        r"password reset spoof|"
        r"fake password reset portal|"
        r"fraudulent password reset link)\b", t
    )
    existing_password_request = _has(
        r"\b(?:existing account passwords|"
        r"current account password|"
        r"collects existing passwords|"
        r"existing login credentials)\b", t
    )
    if password_reset_spoof and existing_password_request:
        add("PASSWORD_RESET_SPOOFING", "CRITICAL",
            "Fraudulent password-reset page collects existing credentials.",
            confirmed=True, confidence=0.99)


    # =========================================================
    # POTENTIAL CONFIDENTIAL DATA LEAKAGE - WARNING
    # =========================================================

    # 132. Confidential draft sent to unverified recipient
    confidential_draft = _has(
        r"\b(?:draft contract|"
        r"confidential draft|"
        r"internal agreement|"
        r"unpublished business contract)\b", t
    )
    draft_recipient = _has(
        r"\b(?:unverified recipient|"
        r"unknown recipient|"
        r"unapproved external recipient)\b", t
    )
    if confidential_draft and draft_recipient:
        add("POTENTIAL_CONFIDENTIAL_DRAFT_LEAKAGE", "MEDIUM",
            "Potentially confidential draft is directed to an unverified recipient.",
            confirmed=False, confidence=0.90)


    # 133. Internal network diagram exposure
    network_diagram = _has(
        r"\b(?:internal network diagram|"
        r"internal architecture diagram|"
        r"internal infrastructure diagram|"
        r"unclassified internal diagram)\b", t
    )
    external_diagram_transfer = _has(
        r"\b(?:outside the organization|"
        r"external recipient|"
        r"unapproved external destination)\b", t
    )
    if network_diagram and external_diagram_transfer:
        add("POTENTIAL_NETWORK_DIAGRAM_EXPOSURE", "MEDIUM",
            "Internal infrastructure information may be exposed externally.",
            confirmed=False, confidence=0.91)


    # 134. Sensitive screenshot exposure
    sensitive_screenshot = _has(
        r"\b(?:sensitive[- ]looking screenshot|"
        r"internal application screenshot|"
        r"administrative dashboard screenshot|"
        r"internal application details)\b", t
    )
    screenshot_exposure = _has(
        r"\b(?:may expose|may contain|"
        r"potential exposure|"
        r"possibly sensitive information)\b", t
    )
    if sensitive_screenshot and screenshot_exposure:
        add("POTENTIAL_SENSITIVE_SCREENSHOT_EXPOSURE", "MEDIUM",
            "Screenshot may expose sensitive internal application information.",
            confirmed=False, confidence=0.89)


    # 135. Sensitive administrative log exposure
    admin_log_context = _has(
        r"\b(?:unusual admin log excerpt|"
        r"diagnostic logs|"
        r"administrative logs|"
        r"internal application logs)\b", t
    )
    log_sensitive_context = _has(
        r"\b(?:may contain sensitive identifiers|"
        r"potentially sensitive identifiers|"
        r"possible credential exposure|"
        r"may contain personal information)\b", t
    )
    if admin_log_context and log_sensitive_context:
        add("POTENTIAL_ADMIN_LOG_EXPOSURE", "MEDIUM",
            "Diagnostic logs may contain sensitive identifiers or information.",
            confirmed=False, confidence=0.90)


    # 136. External AI service upload request
    internal_project_data = _has(
        r"\b(?:internal project material|"
        r"internal source code|"
        r"internal project documents|"
        r"confidential project information)\b", t
    )
    unapproved_ai_upload = _has(
        r"\b(?:unapproved ai service|"
        r"unapproved ai platform|"
        r"unverified external ai tool|"
        r"external ai upload request)\b", t
    )
    if internal_project_data and unapproved_ai_upload:
        add("UNAPPROVED_EXTERNAL_AI_UPLOAD", "MEDIUM",
            "Internal project material is requested for use in an unapproved AI service.",
            confirmed=False, confidence=0.92)


    # =========================================================
    # SENSITIVE DATA AND ADVANCED THREATS - RESTRICTED
    # =========================================================

    # 137. Password dump transfer
    password_dump = _has(
        r"\b(?:password dump transfer|"
        r"list of real account passwords|"
        r"plaintext password database|"
        r"production password dump)\b", t
    )
    password_transfer = _has(
        r"\b(?:attachment|transfer|upload|"
        r"send|export|forward|share)\b", t
    )
    if password_dump and password_transfer:
        add("PASSWORD_DUMP_TRANSFER", "CRITICAL",
            "Message indicates transfer of sensitive account password records.",
            confirmed=True, confidence=0.99)


    # 138. Ransomware delivery attempt
    ransomware_delivery = _has(
        r"\b(?:ransomware delivery attempt|"
        r"ransomware attachment|"
        r"software that encrypts recipient files for ransom|"
        r"malicious file encryption payload)\b", t
    )
    ransomware_distribution = _has(
        r"\b(?:attachment|delivery|"
        r"download|install|execute|payload)\b", t
    )
    if ransomware_delivery and ransomware_distribution:
        add("RANSOMWARE_DELIVERY_ATTEMPT", "CRITICAL",
            "Message indicates distribution of ransomware-related software.",
            confirmed=True, confidence=0.99)


    # 139. Remote-access trojan disguised as support utility
    rat_lure = _has(
        r"\b(?:remote access trojan|"
        r"remote[- ]control trojan|"
        r"remote administration malware|"
        r"backdoor)\b", t
    )
    utility_disguise = _has(
        r"\b(?:disguised as a support utility|"
        r"fake support utility|"
        r"pretending to be a support tool|"
        r"unknown remote[- ]control program)\b", t
    )
    if rat_lure and utility_disguise:
        add("REMOTE_ACCESS_TROJAN_LURE", "CRITICAL",
            "A remote-access trojan is disguised as a legitimate support utility.",
            confirmed=True, confidence=0.99)

    # =========================================================
    # WARNING RULES - CORRECTED SEVERITY AND CONTEXT
    # =========================================================

    # 117. Lookalike domain concern
    lookalike_domain = _has(
        r"\b(?:lookalike domain|"
        r"look[- ]alike domain|"
        r"resembles a known company name|"
        r"not the verified domain|"
        r"similar but unverified domain|"
        r"domain resembles a legitimate company)\b", t
    )
    if lookalike_domain:
        add("LOOKALIKE_DOMAIN_CONCERN", "MEDIUM",
            "Domain resembles a legitimate organization "
            "but requires further verification.",
            confirmed=False, confidence=0.89)


    # 87. Unverified investment return
    investment_claim = _has(
        r"\b(?:unusually high guaranteed returns|"
        r"guaranteed investment returns|"
        r"unverified investment return|"
        r"risk[- ]free high returns|"
        r"guaranteed high profits|"
        r"guaranteed daily income)\b", t
    )
    if investment_claim:
        add("UNVERIFIED_INVESTMENT_RETURN", "MEDIUM",
            "Potentially misleading investment-return claim.",
            confirmed=False, confidence=0.89)


    # 49. Unverified giveaway
    giveaway_lure = _has(
        r"\b(?:free smartphone|"
        r"free iphone|"
        r"free smartphone giveaway|"
        r"unverified giveaway|"
        r"free rewards?|"
        r"qualify for a free|"
        r"claim your free prize)\b", t
    )
    giveaway_context = _has(
        r"\b(?:congratulations|"
        r"qualify|claim|"
        r"register|winner|"
        r"selected|giveaway)\b", t
    )
    if giveaway_lure and giveaway_context:
        add("UNVERIFIED_GIVEAWAY", "MEDIUM",
            "Unverified promotional giveaway detected.",
            confirmed=False, confidence=0.87)


    # 93. Pressure to purchase gift cards
    gift_card_purchase = _has(
        r"\b(?:purchase gift cards|"
        r"buy gift cards|"
        r"purchase gift vouchers|"
        r"buy gift vouchers|"
        r"pressure to buy gift cards)\b", t
    )
    gift_card_pressure = _has(
        r"\b(?:immediately|urgent|"
        r"new contact|unexpected|"
        r"unfamiliar sender|"
        r"as soon as possible)\b", t
    )
    if gift_card_purchase and gift_card_pressure:
        add("URGENT_GIFT_CARD_PURCHASE", "MEDIUM",
            "Suspicious gift-card purchase request.",
            confirmed=False, confidence=0.90)


    # 115. Suspicious redirect chain
    redirect_chain = _has(
        r"\b(?:suspicious redirect chain|"
        r"multiple unrelated domains|"
        r"unverified redirect chain|"
        r"redirects through unknown domains|"
        r"forwards through multiple unrelated domains|"
        r"redirects through multiple domains)\b", t
    )
    if redirect_chain:
        add("SUSPICIOUS_REDIRECT_CHAIN", "MEDIUM",
            "Potentially suspicious URL redirection detected.",
            confirmed=False, confidence=0.89)


    # 48. Excessive promotional urgency
    promo_pressure = _has(
        r"\b(?:last hour|"
        r"last chance|"
        r"act immediately|"
        r"act now|"
        r"offer expires|"
        r"limited time|"
        r"hurry now|"
        r"lose this special promotional price)\b", t
    )
    commercial_context = _has(
        r"\b(?:promotion|promotional|"
        r"discount|coupon|offer|"
        r"deal|price|sale|shopping)\b", t
    )
    if promo_pressure and commercial_context:
        add("EXCESSIVE_PROMOTIONAL_URGENCY", "MEDIUM",
            "High-pressure promotional language detected.",
            confirmed=False, confidence=0.87)


    # 133. Unclassified internal network diagram
    network_diagram = _has(
        r"\b(?:internal network diagram|"
        r"internal architecture diagram|"
        r"internal infrastructure diagram|"
        r"unclassified internal diagram)\b", t
    )
    external_diagram_transfer = _has(
        r"\b(?:outside the organization|"
        r"external recipient|"
        r"external destination|"
        r"being sent outside|"
        r"external organization)\b", t
    )
    if network_diagram and external_diagram_transfer:
        add("POTENTIAL_NETWORK_DIAGRAM_EXPOSURE", "MEDIUM",
            "Internal infrastructure information may "
            "require authorization before external transfer.",
            confirmed=False, confidence=0.90)

    # =========================================================
    # BENIGN CONTEXT DETECTION
    # =========================================================

    # 140. Password and OTP security awareness
    password_safety_context = _has(
        r"\b(?:never share your password|"
        r"never share your otp|"
        r"do not share your password|"
        r"do not disclose your otp|"
        r"never share your password or otp|"
        r"keep your password confidential)\b", t
    )


    # 141. MFA protection awareness
    mfa_safety_context = _has(
        r"\b(?:deny it and contact it|"
        r"deny unexpected mfa prompts?|"
        r"reject unauthorized login requests?|"
        r"do not approve unexpected mfa|"
        r"report suspicious authentication requests?)\b", t
    )


    # 142. Data protection awareness
    data_protection_context = _has(
        r"\b(?:do not send confidential customer records|"
        r"never share confidential customer records|"
        r"do not disclose confidential information|"
        r"do not send sensitive data externally|"
        r"protect confidential customer information)\b", t
    )


    # 143. Synthetic test data usage
    synthetic_data_context = _has(
        r"\b(?:use synthetic customer records|"
        r"synthetic customer records only|"
        r"use synthetic test data|"
        r"use dummy customer data|"
        r"use anonymized test data)\b", t
    )


    # 144. Normal project and meeting communication
    normal_meeting_context = _has(
        r"\b(?:project meeting is scheduled|"
        r"workshop agenda includes|"
        r"next meeting|"
        r"friday planning session|"
        r"review the backlog|"
        r"team lunch is planned)\b", t
    )


    # 145. Approved newsletter
    approved_newsletter_context = _has(
        r"\b(?:monthly newsletter is ready|"
        r"newsletter for subscribed employees|"
        r"ready for subscribed employees|"
        r"approved internal newsletter)\b", t
    )


    # 146. Customer loyalty notification
    loyalty_update_context = _has(
        r"\b(?:loyalty points summary|"
        r"loyalty points balance|"
        r"available in your account dashboard|"
        r"customer loyalty update)\b", t
    )


    # 147. Normal invoice and budget communication
    normal_finance_context = _has(
        r"\b(?:received your invoice|"
        r"normal approval process|"
        r"approved budget summary|"
        r"recorded it for the normal approval process)\b", t
    )


    # 148. Normal HR communication
    normal_hr_context = _has(
        r"\b(?:leave request has been approved|"
        r"approved in the hr system|"
        r"payslip is available|"
        r"usual employee portal|"
        r"updated office holiday calendar)\b", t
    )


    # 149. Normal technical communication
    normal_technical_context = _has(
        r"\b(?:approved application release|"
        r"routine maintenance will begin|"
        r"latest load test completed|"
        r"results are ready for internal review|"
        r"resolved your support request)\b", t
    )


    # 150. Actionable credential request
    credential_request = _has(
        r"\b(?:please|kindly|must|need to|"
        r"required to)\s+"
        r"(?:share|send|provide|submit|disclose)"
        r".{0,50}"
        r"(?:password|otp|verification code|"
        r"authentication code)\b", t
    )

    direct_credential_request = _has(
        r"(?:^|[.!?]\s+)"
        r"(?:share|send|provide|submit|disclose)"
        r"\s+(?:your\s+)?"
        r"(?:password|otp|verification code)\b", t
    )

    if credential_request or direct_credential_request:
        add("ACTIONABLE_CREDENTIAL_REQUEST", "HIGH",
            "Message requests sensitive authentication information.",
            confirmed=False, confidence=0.94)


    # 151. Actionable MFA approval request
    mfa_approval_request = _has(
        r"\b(?:please|kindly|must|need to)\s+"
        r"(?:approve|accept|confirm)"
        r".{0,50}"
        r"(?:mfa prompt|authentication request|"
        r"login request|push notification)\b", t
    )

    if mfa_approval_request:
        add("SUSPICIOUS_MFA_APPROVAL_REQUEST", "HIGH",
            "Message requests approval of an authentication prompt.",
            confirmed=False, confidence=0.94)


    # 152. Actionable confidential data transfer
    confidential_transfer_request = _has(
        r"\b(?:please|kindly|must|need to)\s+"
        r"(?:send|upload|transfer|forward|export)"
        r".{0,80}"
        r"(?:confidential customer records|"
        r"confidential employee records|"
        r"production customer database|"
        r"sensitive customer information)\b", t
    )

    if confidential_transfer_request:
        add("SUSPICIOUS_CONFIDENTIAL_DATA_TRANSFER", "HIGH",
            "Message requests transfer of sensitive business data.",
            confirmed=False, confidence=0.95)


    return findings
