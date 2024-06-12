import Home from "../components/Home/Home";
import Layout from "../components/Layout";
import Profile from "../components/Profile/Profile";
import WallUser from "../components/WallUser/WallUser";

const routes = [
  {
    path: "",
    element: <Layout />,
    children: [
      { path: "/home", element: <Home /> },
      { path: "/profile", element: <Profile /> },
      { path: "/wall/:user_id", element: <WallUser /> },
    ],
  },
];

export default routes;
