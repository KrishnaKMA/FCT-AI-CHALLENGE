# FCT business calendar — adjusts detection thresholds and pre-scaling triggers.

from datetime import datetime, date, timedelta
import calendar


SPRING_MONTHS = {3, 4, 5, 6}
FRIDAY = 4
END_OF_MONTH_BUSINESS_DAYS = 3

INTENSITY = {
    "normal":    1.0,
    "spring":    1.3,
    "friday":    1.6,
    "end_month": 2.0,
    "peak":      3.5,  # Friday + end-of-month + spring
}

BASE_TRANSACTIONS_PER_MIN = 120
PEAK_TRANSACTIONS_PER_MIN = 480


class ClosingCalendar:
    """Business context for a given datetime — intensity, thresholds, and next peak prediction."""

    def __init__(self):
        self._last_context = {}

    def get_context(self, dt: datetime = None) -> dict:
        if dt is None:
            dt = datetime.utcnow()

        friday    = self._is_friday(dt)
        end_month = self._is_end_of_month(dt)
        spring    = self._is_spring(dt)
        peak      = friday and end_month

        intensity = self._compute_intensity(friday, end_month, spring, peak)
        transactions_at_risk = int(BASE_TRANSACTIONS_PER_MIN * intensity)

        context = {
            "timestamp":                      dt.isoformat(),
            "closing_day":                    friday,
            "end_of_month_surge":             end_month,
            "spring_season":                  spring,
            "peak_window":                    peak,
            "intensity":                      round(intensity, 2),
            "active_transactions_at_risk":    transactions_at_risk,
            "expected_request_rate":          int(BASE_TRANSACTIONS_PER_MIN * intensity),
            "latency_threshold_multiplier":   1.5 if peak else (1.25 if friday or end_month else 1.0),
            "request_rate_threshold_multiplier": intensity,
            "fraud_coverage_min_pct":         97.0 if peak else 95.0,
            "pre_scale_recommended":          intensity >= 1.6,
            "next_peak_description":          self._describe_next_peak(dt),
            "business_day":                   dt.weekday() < 5,
        }

        self._last_context = context
        return context

    def predict_next_peak(self, dt: datetime = None) -> dict:
        if dt is None:
            dt = datetime.utcnow()

        days_to_friday = (FRIDAY - dt.weekday()) % 7
        if days_to_friday == 0 and dt.hour >= 17:
            days_to_friday = 7
        next_friday = dt + timedelta(days=days_to_friday)
        next_friday = next_friday.replace(hour=8, minute=30, second=0)

        next_eom = self._next_end_of_month_start(dt)

        if next_friday <= next_eom:
            return {
                "type":         "friday_closing",
                "starts_at":    next_friday.isoformat(),
                "intensity":    INTENSITY["friday"],
                "minutes_until": int((next_friday - dt).total_seconds() / 60),
            }
        else:
            return {
                "type":         "end_of_month_surge",
                "starts_at":    next_eom.isoformat(),
                "intensity":    INTENSITY["end_month"],
                "minutes_until": int((next_eom - dt).total_seconds() / 60),
            }

    def should_prescale(self, dt: datetime = None, lookahead_minutes: int = 30) -> bool:
        if dt is None:
            dt = datetime.utcnow()
        peak = self.predict_next_peak(dt)
        return peak["minutes_until"] <= lookahead_minutes

    def _is_friday(self, dt: datetime) -> bool:
        return dt.weekday() == FRIDAY

    def _is_spring(self, dt: datetime) -> bool:
        return dt.month in SPRING_MONTHS

    def _is_end_of_month(self, dt: datetime) -> bool:
        last_day  = calendar.monthrange(dt.year, dt.month)[1]
        last_date = date(dt.year, dt.month, last_day)
        business_days_from_end = 0
        check = last_date
        while business_days_from_end < END_OF_MONTH_BUSINESS_DAYS:
            if check.weekday() < 5:
                business_days_from_end += 1
            if business_days_from_end < END_OF_MONTH_BUSINESS_DAYS:
                check -= timedelta(days=1)
        return dt.date() >= check

    def _compute_intensity(self, friday: bool, end_month: bool, spring: bool, peak: bool) -> float:
        if peak and spring:    return INTENSITY["peak"]
        if peak:               return INTENSITY["end_month"] * 1.5
        if friday and spring:  return INTENSITY["friday"] * 1.2
        if end_month and spring: return INTENSITY["end_month"] * 1.1
        if friday:             return INTENSITY["friday"]
        if end_month:          return INTENSITY["end_month"]
        if spring:             return INTENSITY["spring"]
        return INTENSITY["normal"]

    def _describe_next_peak(self, dt: datetime) -> str:
        info = self.predict_next_peak(dt)
        mins = info["minutes_until"]
        if mins < 60:
            return f"Next peak in {mins} minutes ({info['type'].replace('_', ' ')})"
        hours = mins // 60
        return f"Next peak in {hours}h {mins % 60}m ({info['type'].replace('_', ' ')})"

    def _next_end_of_month_start(self, dt: datetime) -> datetime:
        for month_offset in range(0, 3):
            year  = dt.year
            month = dt.month + month_offset
            if month > 12:
                month -= 12
                year  += 1

            last_day  = calendar.monthrange(year, month)[1]
            last_date = date(year, month, last_day)
            business_days_from_end = 0
            check = last_date
            while business_days_from_end < END_OF_MONTH_BUSINESS_DAYS:
                if check.weekday() < 5:
                    business_days_from_end += 1
                if business_days_from_end < END_OF_MONTH_BUSINESS_DAYS:
                    check -= timedelta(days=1)

            surge_start = datetime(year, month, check.day, 8, 0, 0)
            if surge_start > dt:
                return surge_start

        return dt + timedelta(days=30)
