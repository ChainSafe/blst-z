pub fn errorIn(err: anyerror, comptime allowed: anytype) bool {
    inline for (allowed) |allowed_err| {
        if (err == allowed_err) return true;
    }
    return false;
}