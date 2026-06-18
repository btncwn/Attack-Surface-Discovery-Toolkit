"""
Security Headers V2
"""

class SecurityHeadersV2:

    WEIGHTS = {
        "Strict-Transport-Security": 25,
        "Content-Security-Policy": 25,
        "X-Frame-Options": 15,
        "X-Content-Type-Options": 10,
        "Referrer-Policy": 15,
        "Permissions-Policy": 10,
    }

    @classmethod
    def analyze(cls, headers: dict):

        score = 0
        present = []
        missing = []

        for header, weight in cls.WEIGHTS.items():

            if header in headers:
                score += weight
                present.append(header)
            else:
                missing.append(header)

        if score >= 90:
            grade = "A"
        elif score >= 75:
            grade = "B"
        elif score >= 60:
            grade = "C"
        elif score >= 40:
            grade = "D"
        else:
            grade = "F"

        return {
            "score": score,
            "grade": grade,
            "present": present,
            "missing": missing
        }
