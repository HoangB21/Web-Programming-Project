import bcrypt from "bcryptjs";
import db from "../models/index";
import { UUID, where } from "sequelize";
import { v4 as uuidv4, v6 as uuidv6 } from "uuid";
import { imageDefaultUser } from "../util/ImageDefault";
const { Op } = require("sequelize");

const salt = bcrypt.genSaltSync(10);

let loginCheck = (id, password) => {
  return new Promise(async (resolve, reject) => {
    try {
      let data = {};
      let user = await db.User.findOne({
        where: {
          user_id: id,
        },
      });
      if (!user || !bcrypt.compareSync(password, user.password)) {
        data = {
          errorCode: 1,
          msg: "Invalid ID or password",
        };
      } else {
        data = {
          errorCode: 0,
          msg: "Successful",
          user: user,
        };
      }
      resolve(data);
    } catch (error) {
      reject(error);
    }
  });
};

let getUser = (userId) => {
  console.log(userId);
  return new Promise(async (resolve, reject) => {
    try {
      let data =
        userId === "ALL"
          ? await db.User.findAll({
              raw: true,
              attributes: { exclude: ["password"] },
            })
          : await db.User.findOne({
              where: { user_id: userId },
              attributes: { exclude: ["password"] },
            });
      if (data) resolve(data);
      else resolve();
    } catch (error) {
      reject(error);
    }
  });
};

let checkEmailExist = async (email) => {
  let data = await db.User.findOne({ where: { email: email } });
  if (data) return true;
  return false;
};

let checkIdExist = async (id) => {
  let data = await db.User.findOne({ where: { user_id: id } });
  if (data) return true;
  return false;
};

let checkProfileNameExist = async (profileName) => {
  let data = await db.User.findOne({ where: { profile_name: profileName } });
  if (data) return true;
  return false;
};

let createUser = (data) => {
  return new Promise(async (resolve, reject) => {
    try {
      if (
        !data.user_id ||
        !data.name ||
        !data.email ||
        !data.password ||
        !data.profile_name ||
        !data.gender ||
        !data.role
      ) {
        resolve({
          errorCode: 1,
          message: "Missing some parameters",
        });
      }
      if (await checkEmailExist(data.email)) {
        resolve({
          errorCode: 2,
          message: "Email exists",
        });
      }
      if (await checkIdExist(data.user_id)) {
        resolve({
          errorCode: 3,
          message: "ID exists",
        });
      }
      if (await checkProfileNameExist(data.profile_name)) {
        resolve({
          errorCode: 4,
          message: "Profile name exists",
        });
      }
      data.password = await hashPassword(data.password);
      await db.User.create({
        user_id: data.user_id,
        name: data.name,
        profile_name: data.profile_name,
        email: data.email,
        password: data.password,
        gender: data.gender,
        dob: data.dob,
        image: imageDefaultUser,
        role: data.role,
      });
      resolve({
        errorCode: 0,
        message: "OK",
      });
    } catch (error) {
      reject(error);
    }
  });
};

let hashPassword = (password) => {
  return new Promise((resolve, reject) => {
    try {
      let hashedPassword = bcrypt.hashSync(password, salt);
      resolve(hashedPassword);
    } catch (error) {
      reject(error);
    }
  });
};

// let updateUser = (data) => {
//   return new Promise(async (resolve, reject) => {
//     let id = data.user_id;
//     try {
//       if (!id) {
//         resolve({
//           errorCode: 1,
//           message: "Missing some parameters",
//         });
//       }
//       let user = await db.User.findOne({ where: { user_id: id }, raw: false });
//       if (!user) {
//         resolve({
//           errorCode: 2,
//           message: "User not found",
//         });
//       }
//       user.profile_name = data.profile_name;
//       user.name = data.name;
//       user.gender = data.gender;
//       user.role = data.role;
//       user.image = data.image;
//       user.dob = data.dob;
//       await user.save();
//       resolve({
//         errorCode: 0,
//         message: "Updated",
//       });
//     } catch (error) {
//       reject(error);
//     }
//   });
// };
let updateUser = (data) => {
  return new Promise(async (resolve, reject) => {
    let id = data.user_id;
    try {
      if (!id) {
        resolve({
          errorCode: 1,
          message: "Missing some parameters",
        });
      }
      let user = await db.User.findOne({ where: { user_id: id }, raw: false });
      if (!user) {
        resolve({
          errorCode: 2,
          message: "User not found",
        });
      }
      if (!bcrypt.compareSync(data.password, user.password)) {
        data = {
          errorCode: 3,
          msg: "Invalid password",
        };
      }
      user.profile_name = data.profile_name;
      user.name = data.name;
      user.gender = data.gender;
      user.role = data.role;
      if (data.newPassword)
        user.password = await hashPassword(data.newPassword);
      user.image = data.image;
      user.dob = data.dob;
      await user.save();
      resolve({
        errorCode: 0,
        message: "Updated",
      });
    } catch (error) {
      reject(error);
    }
  });
};
let deleteUser = (data) => {
  return new Promise(async (resolve, reject) => {
    let id = data.id;
    try {
      if (!id) {
        resolve({
          errorCode: 1,
          message: "Missing some parameters",
        });
      }
      let user = await db.User.findOne({ where: { user_id: id }, raw: false });
      if (!user) {
        resolve({
          errorCode: 2,
          message: "User not found",
        });
      }
      await user.destroy();
      resolve({
        errorCode: 0,
        message: "Deleted",
      });
    } catch (error) {
      reject(error);
    }
  });
};

const getAvatar = async (id) => {
  try {
    let data = await db.User.findOne({ where: { user_id: id } });
    if (!data) {
      return {
        errorCode: 1,
        message: "User not found",
      };
    }
    return data.image;
  } catch (error) {
    console.log(error);
  }
};

const getAvatarByProfile = async (profile_name) => {
  try {
    let data = await db.User.findOne({ where: { profile_name: profile_name } });
    if (!data) {
      return {
        errorCode: 1,
        message: "User not found",
      };
    }
    return getAvatar(data.user_id);
  } catch (error) {
    console.log(error);
  }
};

const getProfileName = async (user_id) => {
  try {
    let data = await db.User.findOne({ where: { user_id } });
    if (!data) {
      return {
        errorCode: 1,
        message: "User not found",
      };
    }
    return data.profile_name;
  } catch (error) {
    console.log(error);
  }
};

const checkReacted = async (data) => {
  try {
    let { user_id, post_id } = data;
    let react = await db.React.findOne({
      where: { user_id: user_id, post_id: post_id },
      raw: false,
    });
    return react ? true : false;
  } catch (error) {
    console.log(error);
    return {
      errorCode: 1,
      message: error.message,
    };
  }
};

const newReact = async (data) => {
  try {
    await db.React.create({ user_id: data.user_id, post_id: data.post_id });
    return {
      errorCode: 0,
      message: "Reacted",
    };
  } catch (error) {
    console.log(error);
    return {
      errorCode: 1,
      message: error.message,
    };
  }
};

const undoReact = async (data) => {
  console.log(data);
  try {
    let react = await db.React.findOne({
      where: { user_id: data.user_id, post_id: data.post_id },
      raw: false,
    });
    await react.destroy();
    return {
      errorCode: 0,
      message: "Undo React",
    };
  } catch (error) {
    console.log(error);
    return {
      errorCode: 1,
      message: "Failed",
    };
  }
};

const getUserIdFromProfile = async (profile_name) => {
  try {
    let user = await db.User.findOne({ where: { profile_name } });
    if (!user) return null;
    return user.user_id;
  } catch (error) {
    console.log(error);
    return null;
  }
};

const newFollow = async (data) => {
  try {
    let follower_id = await getUserIdFromProfile(data.follower);
    let following_id = await getUserIdFromProfile(data.following);
    if (!follower_id || !following_id) {
      return {
        errorCode: 1,
        message: "User not found",
      };
    }
    // console.log(checkFollowing({ follower: follower_id, following: following_id }));
    if (
      await checkFollowing({ follower: follower_id, following: following_id })
    ) {
      return {
        errorCode: 2,
        message: "Exists",
      };
    }
    await db.Follow.create({ follower: follower_id, following: following_id });
    return {
      errorCode: 0,
      message: "Following",
    };
  } catch (error) {
    console.log(error);
    return {
      errorCode: 1,
      message: "Failed",
    };
  }
};

const unfollow = async (data) => {
  let follower_id = await getUserIdFromProfile(data.follower);
  let following_id = await getUserIdFromProfile(data.following);
  try {
    let follow = await db.Follow.findOne({
      where: { follower: follower_id, following: following_id },
      raw: false,
    });
    await follow.destroy();
    return {
      errorCode: 0,
      message: "Unfollow",
    };
  } catch (error) {
    console.log(error);
    return {
      errorCode: 1,
      message: "Failed",
    };
  }
};

const checkFollowing = async (data) => {
  let follower_id = await getUserIdFromProfile(data.follower);
  let following_id = await getUserIdFromProfile(data.following);
  //   console.log(follower_id);
  //   console.log(1);
  //   console.log(following_id);

  try {
    let follow = await db.Follow.findOne({
      where: { follower: follower_id, following: following_id },
      raw: false,
    });
    return follow ? true : false;
  } catch (error) {
    console.log(error);
    return false;
  }
};

const getPostCount = async (profile_name) => {
  try {
    let data = await db.User.findOne({ where: { profile_name: profile_name } });
    if (!data) {
      return {
        errorCode: 1,
        message: "User not found",
      };
    }
    return await db.Post.count({ where: { author: data.user_id } });
  } catch (error) {
    console.log(error);
    return error.message;
  }
};

const getFollowingCount = async (profile_name) => {
  try {
    let data = await db.User.findOne({ where: { profile_name: profile_name } });
    if (!data) {
      return {
        errorCode: 1,
        message: "User not found",
      };
    }
    return await db.Follow.count({ where: { follower: data.user_id } });
  } catch (error) {
    console.log(error);
    return error.message;
  }
};

const getFollowerCount = async (profile_name) => {
  try {
    let data = await db.User.findOne({ where: { profile_name: profile_name } });
    if (!data) {
      return {
        errorCode: 1,
        message: "User not found",
      };
    }
    return await db.Follow.count({ where: { following: data.user_id } });
  } catch (error) {
    console.log(error);
    return error.message;
  }
};

const searchUserByProfile = async (keyword) => {
  try {
    let data = await db.User.findAll({
      where: { profile_name: { [Op.like]: `%${keyword}%` } },
      attributes: ["profile_name", "name", "image"],
    });
    if (!data) {
      return {
        errorCode: 1,
        message: "User not found",
      };
    }
    console.log(data);
    return data;
    2;
  } catch (error) {
    console.log(error);
    return error.message;
  }
};

module.exports = {
  loginCheck: loginCheck,
  getUser: getUser,
  createUser: createUser,
  updateUser: updateUser,
  deleteUser: deleteUser,
  getAvatar,
  getProfileName,
  newFollow,
  unfollow,
  newReact,
  undoReact,
  checkReacted,
  checkFollowing,
  getAvatarByProfile,
  getPostCount,
  getFollowingCount,
  getFollowerCount,
  searchUserByProfile,
};
