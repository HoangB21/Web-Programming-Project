import jwt from "jsonwebtoken";

require("dotenv").config();

const key = process.env.JWT_SECRET_KEY;
const nonSecurePaths = ['/api/login', '/api/create-user'];

const generateToken = (payload) => {

    let token = null;
    try {
        token = jwt.sign(payload, key, { expiresIn: '1h' });
    } catch (error) {
        console.log(error);
    }
    return token;
};

const verifyToken = (token) => {
    let decoded = null;
    try {
        decoded = jwt.verify(token, key);
    } catch (error) {
        console.log(error);
    }
    return decoded;
}

const authenticateToken = (req, res, next) => {
    console.log(req.path);
    if (nonSecurePaths.includes(req.path)) {
        return next();
    }
    // Lấy token từ header của yêu cầu
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) {
        return res.sendStatus(401); // Unauthorized
    }
    let decoded = verifyToken(token);
    if (decoded) {
        if (!decoded.role || decoded.role !== "ADMIN") {
            return res.status(403).json({
                errorCode: -1,
                data: '',
                errorMsg: 'Unauthorized'
            })
        }
        req.user = decoded;
        next();
    }
    else {
        return res.status(401).json({
            errorCode: -1,
            data: '',
            errorMsg: 'Unauthenticated user'
        })
    }
};


module.exports = { generateToken, authenticateToken };