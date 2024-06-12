import React from "react";
import MessageSender from "../MessageSender/MessageSender";

import Grid from "@mui/material/Grid";
import NewFeed from "../NewFeed/NewFeed";
import SearchBox from "../SearchBox/SearchBox";

const Main = () => {
  return (
    <main style={{ width: "100%" }} className="">
      <Grid
        container
        style={{ marginLeft: "3rem" }}
        direction='row'
        justifyContent='center'
        spacing={2}>
        <Grid
          item
          xs={8}>
          <MessageSender></MessageSender>
          <NewFeed></NewFeed>
        </Grid>
        <Grid
          item
          xs={4}>
          <SearchBox></SearchBox>
        </Grid>
      </Grid>
    </main>
  );
};

export default Main;
