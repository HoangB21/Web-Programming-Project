const db = require("../models/index");
import userService from '../services/userServices'

const createComment = async (data) => {
    try {
        const comment = await db.Comment.create({
            owner: data.owner,
            post_id: data.post_id,
            content: data.content,
        });
        return comment;
    } catch (error) {
        throw new Error(error.message);
    }
};

const getCommentByPostId = async (postId) => {
    try {
        const comments = await db.Comment.findAll({ where: { post_id: postId } });
        for (let i = 0; i < comments.length; i++) {
            comments[i].avatar = await userService.getAvatar(comments[i].owner);
            comments[i].avatar = Buffer.from(comments[i].avatar, 'base64').toString('binary');
            comments[i].owner = await userService.getProfileName(comments[i].owner);
        }
        return comments;
    } catch (error) {
        console.log(error);
        throw new Error(error.message);
    }
};

module.exports = {
    createComment,
    getCommentByPostId,
};
