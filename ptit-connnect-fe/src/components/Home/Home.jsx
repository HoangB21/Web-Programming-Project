import React, { useEffect } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import Main from "../Main/Main";

const Home = () => {
  const navigate = useNavigate();
  const location = useLocation();
  useEffect(() => {
    if (location.pathname === "/") {
      navigate("/home");
    }    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  return (
    <React.Fragment>
      <Main></Main>
    </React.Fragment>
  );
};

export default Home;
