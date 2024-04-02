const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const config = require('config');
const { validationResult, check } = require('express-validator');

const User= require('../models/User');


// @route    POST api/users
// @desc     Register a user
// @access   Public
router.post('/', [
    check('name', 'Please add name')
      .not()
      .isEmpty(),
    check('email', 'Please include a valid email').isEmail(),
    check(
         'password', 
         'Please enter a password with 6 or more characters'
        ).isLength({ min:6})
  ],
    async (req,res) => {
       const errors = validationResult(req);
       if(!errors.isEmpty()){
         return res.status(400).json({ errors:errors.array() });
       }
       //上面的if用于显示error的具体内容
       
       const{ name, email, password } = req.body;

         try{
            let user = await User.findOne({ email });//这个email是email:email的缩写
            if(user) {
                return res.status(400).json({ msg:'User already exists'});
            }
            
            user = new User({
                name,
                email,
                password
            });

            const salt = await bcrypt.genSalt(10);//使用 await 关键字等待生成密码盐的操作，genSalt 方法生成一个随机的密码盐，用于加密用户密码。

            user.password = await bcrypt.hash(password, salt);//使用 await 关键字等待密码加密操作，将用户提交的密码加密，并将加密后的密码赋值给用户实例的 password 属性

            await user.save();

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
            res.status(500).send('Server error');
         }
    }
);

module.exports = router;

//通常情况下，await 用于等待异步操作的完成，特别是在涉及到耗时操作的情况下。在不使用 await 的情况下，JavaScript 代码会继续执行后续的操作，而不会等待异步操作完成。

//以 const salt = await bcrypt.genSalt(10); 为例，如果不使用 await，则代码会继续执行下一行，而不会等待 bcrypt.genSalt(10) 返回一个 Promise 对象的解析结果。这意味着在 const salt 被赋值之前，可能会执行后续的代码，导致后续的操作无法正确地使用 salt。

//如果不使用 await，而是在异步操作后面使用 .then() 方法处理异步操作的结果，也可以实现等待异步操作完成后再继续执行后续的操作。但是，这样会使代码变得更加复杂，而 await 关键字可以使异步代码看起来更像同步代码，更易于理解和维护。

//在这个特定的例子中，如果不使用 await，则 const salt 可能会在异步操作完成之前被赋值为 undefined 或者其他初始值，导致后续的代码无法正确地使用 salt。因此，为了确保在获取到密码盐之后再继续执行后续的操作，需要使用 await 来等待异步操作的完成。
