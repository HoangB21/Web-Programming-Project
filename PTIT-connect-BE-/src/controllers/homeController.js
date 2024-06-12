import CRUDservices from "../services/CRUDservices";

let getHomePage = (req, res) => {
    return res.render("homepage.ejs");
}

let getCrud = (req, res) => {
    return res.render("createUser.ejs");
}

let postCrud = async (req, res) => {
    let msg = await CRUDservices.createUser(req.body);
    return res.send("post crud");
}

let getUserManagement = async (req, res) => {
    let users = await CRUDservices.getUser('ALL');
    return res.render("userManagement.ejs", {
        data: users
    })
}

let editUser = async (req, res) => {
    let userId = req.query.id;
    let user = await CRUDservices.getUser(userId);
    if (user) {
        return res.render("editUser.ejs", {
            user: user
        })
    }
    else {
        return res.send("User not found!")
    }
}

let updateUser = async (req, res) => {
    let userId = req.query.id;
    let data = req.body;
    await CRUDservices.updateUser(data, userId);
    return res.send('update completed');
}

let deleteUser = async (req, res) => {
    let userId = req.query.id;
    await CRUDservices.deleteUser(userId);
    return res.send("deleted")
}

module.exports = {
    getHomePage: getHomePage,
    getCrud: getCrud,
    postCrud: postCrud,
    getUserManagement: getUserManagement,
    editUser: editUser,
    updateUser: updateUser,
    deleteUser: deleteUser,
}