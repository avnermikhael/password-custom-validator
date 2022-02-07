/* eslint-disable consistent-return */
/* eslint-disable func-names */
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const uniqueValidator = require('mongoose-unique-validator');
const randomstring = require('randomstring');
const { isValidPassword } = require('mongoose-custom-validators');

const userSchema = new mongoose.Schema({
  fullname: {
    type: String,
    required: true,
    minlength: 3,
    maxlength: 255,
  },
  nik: {
    type: String,
    minlength: 6,
    maxlength: 255,
    trim: true,
    default: null,
    validate: {
      async validator(value) {
        if (value === null) { return true; }
        const exists = await mongoose.model('User').countDocuments({ nik: value });
        return !exists;
      },
      message: (props) => `${props.value} is already exits`,
    },

  },
  type: {
    type: String,
    enum: ['telkom', 'partner'],
  },
  invitationCode: {
    type: String,
    default: null,
  },
  email: {
    type: String,
    unique: true,
    minlength: 3,
    maxlength: 255,
  },
  password: {
    type: String,
    required: true,
  },
  emailVerCode: {
    type: String,
    minlength: 3,
    maxlength: 255,
    default: randomstring.generate(),
  },
  emailVerStatus: {
    type: Boolean,
    default: false,
  },
  phoneNumber: {
    type: String,
    minlength: 3,
    maxlength: 255,
    trim: true,
    default: null,
    validate: {
      async validator(value) {
        if (value === null) { return true; }
        const exists = await mongoose.model('User').countDocuments({ phoneNumber: value });
        return !exists;
      },
      message: () => 'phone number is already exists',
    },

  },
  avatar: {
    default: null,
    type: Object,
    url: {
      small: { type: String, trim: true },
      medium: { type: String, trim: true },
      normal: { type: String, trim: true },
    },
    fileName: { type: String, trim: true },
  },
  country: {
    type: String,
    minlength: 3,
    maxlength: 255,
    trim: true,
    default: null,
  },
  companyId: {
    type: String,
    default: null,
  },
  resetPasswordToken: {
    type: String,
  },
  resetPasswordExpires: {
    type: Date,
  },
  jobPosition: {
    type: String,
    minlength: 3,
    maxlength: 255,
    trim: true,
    default: null,
  },
  roles: {
    type: Array,
    default: ['default'],
    validate: {
      async validator(value) {
        const exists = await mongoose.model('Role').find().where('_id').in(value);
        return exists.length === value.length;
      },
      message: (props) => `one or more roles [${props.value}] is invalid`,
    },
    ref: 'Role',
  },
  positionMapping: {
    type: mongoose.Schema({
      position: {
        _id: { type: String },
        name: { type: String },
        band: { type: Number },
      },
      unit: {
        _id: { type: String },
        name: { type: String },
      },
      division: {
        _id: { type: String },
        name: { type: String },
      },
    }, { _id: false }),
    default: null,
  },
  deletedAt: {
    type: Date,
  },
  created: {
    type: mongoose.Schema({
      by: {
        type: String,
      },
      at: {
        type: Date,
      },
      userId: {
        type: String,
      },
    }, { _id: false }),
    default: null,
  },
  updated: {
    type: mongoose.Schema({
      by: {
        type: String,
      },
      at: {
        type: Date,
      },
      userId: {
        type: String,
      },
    }, { _id: false }),
    default: null,
  },
  meta: mongoose.Schema.Types.Mixed,
}, { timestamps: false });

userSchema.plugin(uniqueValidator, { message: '{PATH} is already exists.' });

userSchema.path('password').validate(async function (value) {
  const isTrue = await isValidPassword(value, { nonalpha: false, minlength: 8 });
  if (isTrue) {
    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash(value, salt);
    // jika opterator nya updateOne
    if (this.op === 'updateOne') {
      this.getUpdate().$set.password = hash;
    } else { // jika save
      this.password = hash;
    }
  }
  return isTrue;
}, 'Password must be at least 8 characters, mix of letters and numbers, include both upper and lower case');

// Global Static function
Object.assign(userSchema.statics, require('../../libraries/mongoose/statics'));

// Custom Static function
Object.assign(userSchema.statics, require('./mongoose/customStatics'));

// Custom Method function
Object.assign(userSchema.methods, require('./mongoose/customMethods'));

const User = mongoose.model('User', userSchema);
module.exports = User;
