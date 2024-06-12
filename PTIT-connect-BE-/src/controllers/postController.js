import postServices from "../services/postServices";

const createNewPostController = async (req, res) => {
  try {
    const message = await postServices.createNewPostService(req.body);
    return res.status(200).json(message);
  } catch (error) {
    console.log(error);
    return res.status(500).json(error);
  }
};

const getMyPostController = async (req, res) => {
  try {
    const message = await postServices.getMyPostService(
      req.query.userid,
      +req.query.lim
    );
    return res.status(200).json(message);
  } catch {
    console.log(error);
    return res.status(500).json(error);
  }
};

const getPostByProfile = async (req, res) => {
  try {
    const message = await postServices.getPostByProfile(
      req.query.profile_name,
    );
    return res.status(200).json(message);
  } catch {
    console.log(error);
    return res.status(500).json(error);
  }
}

module.exports = {
  createNewPostController: createNewPostController,
  getMyPostController: getMyPostController,
  getPostByProfile,
};
