import React from "react";
import { Outlet } from "react-router-dom";
import SideBar from "./Sidebar/SideBar";
import AuthGuard from "../guard/AuthGuard";

const Layout = () => {
  return (
    <div
      id='app'
      style={({ height: "100vh" }, { display: "flex" })}>
      <SideBar></SideBar>
      <div
        style={{
          width: "100%",
          marginLeft: "250px",
        }}>
        <AuthGuard element={<Outlet />}></AuthGuard>
      </div>
    </div>
  );
};

export default Layout;
