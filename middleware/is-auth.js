module.exports = (req, resp, next) => {
    if (!req.session.isLoggedIn) {
        return resp.redirect('/login');
    }
    next();
}