//validate the token and access protected route's
const jwt = require('jsonwebtoken');
const config = require('config');

module.exports = function(req,res,next) {
    //Get token from the header
    const token = req.header('x-auth-token');

    //Check if not token
    if(!token) {
        return res.status(401).json({ msg:'No token, authorization denied '});
    }

    try {
        const decoded = jwt.verify(token, config.get('jwtSecret'));
        //jwtSecret 的作用是确保生成的 JWT 令牌具有一定的安全性，只有持有正确密钥的服务端才能够正确解码和验证令牌，并提取出其中的用户信息

        req.user = decoded.user;
        next();
    } catch (err) {
        res.status(401).json({ msg:'Token is not valid '});
    }
}