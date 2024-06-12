import express from "express";
import userController from "../controllers/userController";
import postController from "../controllers/postController";
import commentController from "../controllers/commentController";
import { authenticateToken } from "../middleware/JWTMiddleware"

let router = express.Router();

let initWebRoutes = (app) => {
  router.all('*', authenticateToken); // JWT

  router.post("/api/login", userController.loginUserController);
  router.get("/api/get-user", userController.getUserController);
  router.post("/api/create-user", userController.createUserController);
  router.put("/api/update-user", userController.updateUserController);
  router.delete("/api/delete-user", userController.deleteUserController);
  router.get("/api/get-user-avatar", userController.getUserAvatar);
  router.get("/api/get-user-profile-name", userController.getUserProfileName);
  router.post("/api/follow", userController.userFollow);
  router.delete("/api/unfollow", userController.userUnfollow);
  router.get("/api/check-user-following", userController.checkUserFollowing);
  router.post("/api/react", userController.userReact);
  router.delete("/api/undo-react", userController.userUndoReact);
  router.get("/api/check-reacted", userController.checkUserReacted);
  router.get("/api/get-post-count", userController.getPostCount);
  router.get("/api/get-follower-count", userController.getFollowerCount);
  router.get("/api/get-following-count", userController.getFollowingCount);
  router.get("/api/search-user", userController.searchUserByProfile);

  router.post("/api/create-post", postController.createNewPostController);
  router.get("/api/get-my-post", postController.getMyPostController);
  router.get("/api/get-user-post", postController.getPostByProfile);

  router.post("/api/create-comment", commentController.createCommentController);
  router.get("/api/get-comment-by-post", commentController.getCommentByPostId);
  return app.use("/", router);
};

module.exports = initWebRoutes;
