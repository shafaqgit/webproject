const mongoose=require('mongoose');
const bcrypt=require('bcrypt'); // for hashing the password so that we can match them later
//fields of customers
const userSchema=new mongoose.Schema({
firstName:{
    type: String,
    required: true,
    trim: true,
    min: 5,
    max: 15
},

lastName:{
    type: String,
    required: true,
    trim: true,
    min: 5,
    max: 15
},
cnic:{
    type:String,
    required: true,
    trim:true,
    unique:true
},
email:{
    type: String,
    required: true,
    trim: true,
    unique: true,
    lowercase: true
},
gender:{
    type:String,
    enum:['male','female']
},
hashed_password: {
    type: String,
    default: ''
},
contactNumber:{
    type: String
},

role:{
    type: String,
    enum: ['admin','user'],
    default:'admin'
}

},{timestamps: true});//mongoose adds created at and updated at properties to your schema

userSchema.virtual('password').set(function(password){
    this.hash_password=bcrypt.hashSync(password,10);
});
userSchema.methods={
    authenticate: function(password){
        return bcrypt.compare(password,this.hash_password)
    }
}

/*

//generating hash value:
userSchema.virtual('password').set(function(password){
    this._password=password;
});

//comparing user password and hash
userSchema.pre("save", function (next) {
    // store reference
    const user = this;
    if (user._password === undefined) {
        return next();
    }
    bcrypt.genSalt(10, function (err, salt) {
        if (err) console.log(err);
        // hash the password using our new salt
        bcrypt.hash(user._password, salt, function (err, hash) {
            if (err) console.log(err);
            user.hashed_password = hash;
            next();
        });
    });
});

//comparision k liye object=comparePassword:
userSchema.methods = {
    comparePassword: function(candidatePassword, cb) {
        bcrypt.compare(candidatePassword, this.password, function(err, isMatch) {
            if (err) 
            return cb(err);
            cb(null, isMatch);
        });
    }
}
*/

//we are writing a model=schema
module.exports=mongoose.model('User',userSchema);