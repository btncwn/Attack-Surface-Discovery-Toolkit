from modules.email_security.intelligence import build_email_security_intelligence

result = build_email_security_intelligence(
    domain="example.com",
    spf_result={"status": "PASS"},
    dkim_result={"status": "VERIFIED"},
    dmarc_result={"policy": "reject"},
    mta_sts_result={"enabled": True, "policy_mode": "enforce"},
    tls_rpt_result={"enabled": True},
    starttls_result={"starttls_supported_hosts": 1},
    provider_result={"provider": "Microsoft 365"}
)

print(result)
