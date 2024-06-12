const commentService = require("../services/commentServices");

const createCommentController = async (req, res) => {
    // console.log(req.body);
    try {
        const comment = await commentService.createComment(req.body);
        res.status(201).json(comment);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
};

const getCommentByPostId = async (req, res) => {
    try {
        const { postId } = req.query;
        const comments = await commentService.getCommentByPostId(postId);
        res.status(200).json(comments);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
};


module.exports = {
    createCommentController,
    getCommentByPostId
};
