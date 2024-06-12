import axios from "axios";
import React, { useEffect, useState } from "react";
import Feed from "./Feed/Feed";
import "./NewFeed.scss";
import { Buffer } from "buffer";
import comparePostTime from "../../utils/TranformTime";
const NewFeed = () => {
  const [listFeed, setListFeed] = useState([]);
  const getPost = async () => {
    const user = JSON.parse(localStorage.getItem("user"));
    const response = await axios.get("http://localhost:9999/api/get-my-post", {
      params: {
        userid: user.user_id,
        lim: 10,
      },
    });
    response.data.forEach((data) => {
      data.createdAt = comparePostTime(data.createdAt);
      if (data.media) {
        data.media.forEach((item) => {
          if (item.file_content) {
            item.file_content.data = Buffer.from(
              item.file_content.data,
              "base64"
            ).toString("binary");
          }
          // console.log(item);
        });
      }
    });
    setListFeed([...response.data]);
  };
  useEffect(() => {
    getPost();
  }, []);
  return (
    <div className='newfeed'>
      {listFeed.map((feed, index) => (
        <Feed
          key={index}
          value={{ feed }}></Feed>
      ))}
    </div>
  );
};

export default NewFeed;
