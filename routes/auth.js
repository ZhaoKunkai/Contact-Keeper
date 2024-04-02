const express = require('express');
const router=express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const config = require('config');
const auth = require('../middleware/auth')
const { validationResult, check } = require('express-validator');

const User= require('../models/User');


// @route    GET api/auth
// @desc     Get logged in user
// @access   Private
router.get('/', auth, async (req,res) => {//Wants protected route, add auth
    try {
      const user = await User.findById(req.user.id).select('-password');
      res.json(user);
    } catch (err) {
      console.error(err.message);
      res.status(500).send('Server error');
    }
});

// @route    POST api/auth
// @desc     Auth user & get token
// @access   Public
router.post('/', [
   check('email', 'Please include a valid email').isEmail(),
     check('password', 'Password is required').exists()
], async (req,res) => {
   const errors = validationResult(req);
       if(!errors.isEmpty()){
         return res.status(400).json({ errors:errors.array() });
       }

       const { email, password } = req.body;

       try {
          let user = await User.findOne({ email });
          
          if(!user){
            return res.status(400).json({ msg:' Invalid Credentials '});//No such email
          }

          const isMatch = await bcrypt.compare(password, user.password);

          if(!isMatch){
            return res.stauts(400).json({ msg:' Invalid Credentials '});//Password not match
          }

          const payload = {
            user:{
              id:user.id
            }
          }
          
          jwt.sign(payload, config.get('jwtSecret'), { 
             expiresIn: 36000
           }, (err, token) => {
             if(err) throw err;
             res.json({ token });
           }
           /* 创建一个 JWT 的 payload，其中包含用户的 ID。然后使用 jwt.sign 方法生成 JWT，其中包含了 payload、JWT 密钥和过期时间。

           如果 JWT 生成成功，则将生成的 token 作为 JSON 响应返回给客户端，如果生成失败，则抛出错误。 */
          );
       } catch (err) {
           console.error(err.message);
           res.status(500).send('Server Error');
       }
    }
);

module.exports = router;