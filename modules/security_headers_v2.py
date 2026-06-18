"""
Security Headers V2

Modern security header scoring engine.
Keeps legacy modules/security_headers.py untouched.
"""


class SecurityHeadersV2:
    """Modern security headers scoring engine."""

    @classmethod
    def analyze(cls, headers: dict) -> dict:
        score = 0
        details = {}
        present = []
        missing = []

        # HSTS - 25 points
        hsts = headers.get("Strict-Transport-Security")
        hsts_score = 0
        if hsts:
            present.append("Strict-Transport-Security")
            hsts_score += 15
            value = hsts.lower()

            if "includesubdomains" in value:
                hsts_score += 5
            if "preload" in value:
                hsts_score += 3
            if "max-age" in value:
                try:
                    max_age = int(value.split("max-age=")[1].split(";")[0])
                    if max_age >= 31536000:
                        hsts_score += 2
                except Exception:
                    pass
        else:
            missing.append("Strict-Transport-Security")

        hsts_score = min(hsts_score, 25)
        score += hsts_score
        details["Strict-Transport-Security"] = hsts_score

        # CSP - 25 points
        csp = headers.get("Content-Security-Policy")
        csp_score = 0
        if csp:
            present.append("Content-Security-Policy")
            csp_score += 15
            value = csp.lower()

            if "frame-ancestors" in value:
                csp_score += 5
            if "default-src" in value:
                csp_score += 3
            if "script-src" in value:
                csp_score += 2
        else:
            missing.append("Content-Security-Policy")

        csp_score = min(csp_score, 25)
        score += csp_score
        details["Content-Security-Policy"] = csp_score

        # X-Frame-Options - 15 points
        xfo = headers.get("X-Frame-Options")
        xfo_score = 0
        if xfo:
            present.append("X-Frame-Options")
            xfo_score += 10
            value = xfo.upper()
            if "DENY" in value:
                xfo_score += 5
            elif "SAMEORIGIN" in value:
                xfo_score += 3
        else:
            missing.append("X-Frame-Options")

        xfo_score = min(xfo_score, 15)
        score += xfo_score
        details["X-Frame-Options"] = xfo_score

        # X-Content-Type-Options - 10 points
        xcto = headers.get("X-Content-Type-Options")
        xcto_score = 0
        if xcto:
            present.append("X-Content-Type-Options")
            if "nosniff" in xcto.lower():
                xcto_score = 10
            else:
                xcto_score = 5
        else:
            missing.append("X-Content-Type-Options")

        score += xcto_score
        details["X-Content-Type-Options"] = xcto_score

        # Referrer-Policy - 15 points
        ref = headers.get("Referrer-Policy")
        ref_score = 0
        if ref:
            present.append("Referrer-Policy")
            ref_score += 8
            value = ref.lower()
            if "no-referrer" in value:
                ref_score += 7
            elif "strict-origin-when-cross-origin" in value:
                ref_score += 5
            elif "same-origin" in value:
                ref_score += 4
        else:
            missing.append("Referrer-Policy")

        ref_score = min(ref_score, 15)
        score += ref_score
        details["Referrer-Policy"] = ref_score

        # Permissions-Policy - 10 points
        pp = headers.get("Permissions-Policy")
        pp_score = 0
        if pp:
            present.append("Permissions-Policy")
            pp_score += 7
            value = pp.lower()
            for feature in ["camera", "microphone", "geolocation"]:
                if feature in value:
                    pp_score += 1
        else:
            missing.append("Permissions-Policy")

        pp_score = min(pp_score, 10)
        score += pp_score
        details["Permissions-Policy"] = pp_score

        if score >= 90:
            grade = "A"
            status = "EXCELLENT"
        elif score >= 75:
            grade = "B"
            status = "GOOD"
        elif score >= 60:
            grade = "C"
            status = "FAIR"
        elif score >= 40:
            grade = "D"
            status = "POOR"
        else:
            grade = "F"
            status = "CRITICAL"

        return {
            "score": score,
            "grade": grade,
            "status": status,
            "details": details,
            "present": present,
            "missing": missing
        }
