import { Route, BrowserRouter as Router, Routes } from "react-router-dom";
import "./App.css";
import Home from "./components/Home/Home";
import Layout from "./components/Layout";
import Login from "./components/Login/Login";
import Profile from "./components/Profile/Profile";
import Register from "./components/Register/Register";
import WallUser from "./components/WallUser/WallUser";
import { useEffect } from "react";

function App() {
  return (
    <Router>
      <Routes>
        <Route
          path='/'
          element={<Layout />}>
          <Route
            path=''
            element={<Home />}
          />
          <Route
            path='/home'
            element={<Home />}
          />
          <Route
            path='/profile'
            element={<Profile />}
          />
          <Route
            path='/wall/:user_id'
            element={<WallUser />}
          />
        </Route>
        <Route
          path='/login'
          element={<Login />}
        />
        <Route
          path='/register'
          element={<Register />}
        />
      </Routes>
    </Router>
  );
}

export default App;
