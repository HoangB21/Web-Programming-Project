import userServices from "../services/userServices";
import jwt from "../middleware/JWTMiddleware"

let loginUserController = async (req, res) => {
  let id = req.body.id;
  let password = req.body.password;
  if (!id || !password) {
    return res.status(500).json({
      errorCode: 1,
      msg: "Missing ID or password",
    });
  }
  let data = await userServices.loginCheck(id, password);
  if (!data.user) {
    return res.status(500).json({
      errorCode: data.errorCode,
      msg: data.msg,
    });
  }

  return res.status(200).json({
    errorCode: data.errorCode,
    msg: data.msg,
    user: data.user,
    token: jwt.generateToken(data.user)
  });
};

let getUserController = async (req, res) => {
  let id = req.query.id;
  if (!id) {
    return res.status(200).json({
      errorCode: 1,
      msg: "Missing parameter",
      user: null,
    });
  }

  let data = await userServices.getUser(id);
  return res.status(200).json({
    errorCode: 0,
    msg: "get ok",
    user: data,
  });
};

let createUserController = async (req, res) => {
  let message = await userServices.createUser(req.body);
  return res.status(200).json(message);
};

let updateUserController = async (req, res) => {
  let message = await userServices.updateUser(req.body);
  return res.status(200).json(message);
};

let deleteUserController = async (req, res) => {
  let message = await userServices.deleteUser(req.body);
  return res.status(200).json(message);
};

let userCreatePost = async (req, res) => {
  let message = await userServices.createPost(req.body);
  return res.status(200).json(message);
};

const getUserAvatar = async (req, res) => {
  const { user_id, profile_name } = req.query;
  let message = user_id
    ? await userServices.getAvatar(user_id)
    : await userServices.getAvatarByProfile(profile_name);
  return res.status(200).json(message);
};

const getUserProfileName = async (req, res) => {
  const { userid } = req.query;
  let message = await userServices.getProfileName(userid);
  return res.status(200).json(message);
};

const userReact = async (req, res) => {
  let message = await userServices.newReact(req.body);
  return res.status(200).json(message);
};

const userUndoReact = async (req, res) => {
  let message = await userServices.undoReact(req.query);
  return res.status(200).json(message);
};

const checkUserReacted = async (req, res) => {
  let message = await userServices.checkReacted(req.query);
  return res.status(200).json(message);
};

const userFollow = async (req, res) => {
  let message = await userServices.newFollow(req.body);
  return res.status(200).json(message);
};

const userUnfollow = async (req, res) => {
  let message = await userServices.unfollow(req.query);
  return res.status(200).json(message);
};

const checkUserFollowing = async (req, res) => {
  let message = await userServices.checkFollowing(req.query);
  return res.status(200).json(message);
};

const getPostCount = async (req, res) => {
  const { profile_name } = req.query;
  let message = await userServices.getPostCount(profile_name);
  return res.status(200).json(message);
};

const getFollowerCount = async (req, res) => {
  const { profile_name } = req.query;
  let message = await userServices.getFollowerCount(profile_name);
  return res.status(200).json(message);
};

const getFollowingCount = async (req, res) => {
  const { profile_name } = req.query;
  let message = await userServices.getFollowingCount(profile_name);
  return res.status(200).json(message);
};

const searchUserByProfile = async (req, res) => {
  const { keyword } = req.query;
  let message = await userServices.searchUserByProfile(keyword);
  return res.status(200).json(message);
};

module.exports = {
  loginUserController: loginUserController,
  getUserController: getUserController,
  createUserController: createUserController,
  updateUserController: updateUserController,
  deleteUserController: deleteUserController,
  userCreatePost: userCreatePost,
  getUserAvatar,
  getUserProfileName,
  userFollow,
  userUnfollow,
  userReact,
  userUndoReact,
  checkUserReacted,
  checkUserFollowing,
  getPostCount,
  getFollowerCount,
  getFollowingCount,
  searchUserByProfile,
};
