import { UUID, where } from "sequelize";
import db from "../models/index";
import { useCLS } from "sequelize";
const { v4: uuidv4 } = require("uuid");
import userService from '../services/userServices'

const createNewPostService = async (data) => {
  // console.log(data);
  try {
    if (!data.userid) {
      return {
        errorCode: 1,
        message: "Missing user's ID",
      };
    }
    if (!data.content) {
      return {
        errorCode: 2,
        message: "Missing post content",
      };
    }
    const user = await db.User.findOne({ where: { user_id: data.userid } });
    if (!user) {
      return {
        errorCode: 3,
        message: "User not found",
      };
    }
    const postId = uuidv4();
    await db.Post.create({
      post_id: postId,
      author: data.userid,
      content: data.content,
    });
    await createPostMediaService(postId, data.media);
  } catch (error) {
    console.log(error);
  }
};

const createPostMediaService = async (postId, media) => {
  for (var i = 0; i < media.length; i++) {
    await db.MediaFile.create({ post_id: postId, file_content: media[i] });
  }
};

const getMyPostService = async (userid, lim) => {
  try {
    if (!userid) {
      return {
        errorCode: 1,
        message: "Missing user's ID",
      };
    }
    if (!lim) {
      return {
        errorCode: 1,
        message: "Missing limit",
      };
    }
    const posts =
      lim === "ALL"
        ? await db.Post.findAll({
          where: { author: userid }, order: [
            ['createdAt', 'DESC'],
          ],
        })
        : await db.Post.findAll({
          where: { author: userid },
          raw: true,
          limit: lim,
          order: [
            ['createdAt', 'DESC'],
          ],
        });
    for (var i = 0; i < posts.length; i++) {
      posts[i].media = await getPostMedia(posts[i].post_id);
      posts[i].image = await userService.getAvatar(posts[i].author);
      posts[i].image = Buffer.from(posts[i].image, 'base64').toString('binary');
      posts[i].author = await userService.getProfileName(posts[i].author);
    }
    // console.log(posts);
    return posts;
  } catch (error) {
    console.log(error);
  }
};

const getPostMedia = async (postId) => {
  try {
    const data = await db.MediaFile.findAll({
      where: { post_id: postId },
    });
    if (!data) return "aaaa";
    return data;
  } catch (error) {
    console.log(error);
    return []
  }
};

const getPostByProfile = async (profile_name) => {
  console.log(profile_name);
  try {
    const user = await db.User.findOne({ where: { profile_name } });
    if (!user) {
      return {
        errorCode: 1,
        message: "User not found",
      };
    }
    const posts = await db.Post.findAll({
      where: { author: user.user_id }, order: [
        ['createdAt', 'DESC'],
      ],
    });
    for (var i = 0; i < posts.length; i++) {
      posts[i].media = await getPostMedia(posts[i].post_id);
      posts[i].image = await userService.getAvatar(posts[i].author);
      posts[i].image = Buffer.from(posts[i].image, 'base64').toString('binary');
      posts[i].author = await userService.getProfileName(posts[i].author);
    }
    return posts;
  }
  catch (error) {
    console.log(error);
    return error.message;
  }
}

module.exports = {
  createNewPostService: createNewPostService,
  getMyPostService,
  getPostByProfile
};
