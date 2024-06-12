import { Avatar } from "@mui/material";
import React, { useEffect, useRef, useState } from "react";
import { useParams } from "react-router-dom";
import "swiper/css";
import "swiper/css/navigation";
import "swiper/css/pagination";
import "swiper/css/scrollbar";
import "../NewFeed/Feed/Feed.scss";
import "./WallUser.scss";
import { Buffer } from "buffer";

import "swiper/swiper-bundle.css";
// Library

// Icon
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import axios from "axios";
import comparePostTime from "../../utils/TranformTime";
import Feed from "../NewFeed/Feed/Feed";
const WallUser = () => {
  let { user_id } = useParams();
  const [listFeed, setListFeed] = useState([]);
  const [avatar, setAvatar] = useState("");
  const [postCount, setPostCount] = useState(0);
  const [followerCount, setFollowerCount] = useState(0);
  const [followingCount, setFollowingCount] = useState(0);
  const [fololow, setFollow] = useState(false);
  const getPost = async () => {
    const response = await axios.get(
      "http://localhost:9999/api/get-user-post",
      {
        params: {
          profile_name: user_id,
        },
      }
    );
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
        });
      }
    });
    setListFeed([...response.data]);
  };

  const initWall = async () => {
    let response = await axios.get(
      "http://localhost:9999/api/get-user-avatar",
      {
        params: {
          profile_name: user_id,
        },
      }
    );
    const image = Buffer.from(response.data, "base64").toString("binary");
    setAvatar(image);
    response = await axios.get("http://localhost:9999/api/get-post-count", {
      params: {
        profile_name: user_id,
      },
    });
    setPostCount(response.data);

    response = await axios.get("http://localhost:9999/api/get-follower-count", {
      params: {
        profile_name: user_id,
      },
    });
    setFollowerCount(response.data);

    response = await axios.get(
      "http://localhost:9999/api/get-following-count",
      {
        params: {
          profile_name: user_id,
        },
      }
    );
    setFollowingCount(response.data);
  };
  useEffect(() => {
    getPost();
    initWall();
    //
    const user = JSON.parse(localStorage.getItem("user"));
    const checkFollow = async () => {
      const response = await axios.get(
        "http://localhost:9999/api/check-user-following",
        {
          params: {
            follower: user.profile_name,
            following: user_id,
          },
        }
      );
      console.log(response);
      setFollow(response.data);
    };
    checkFollow();
  }, []);
  const sendFollow = async () => {
    const user = JSON.parse(localStorage.getItem("user"));
    if (!fololow) {
      await axios.post("http://localhost:9999/api/follow", {
        follower: user.profile_name,
        following: user_id,
      });
    } else {
      await axios.delete("http://localhost:9999/api/unfollow", {
        params: {
          follower: user.profile_name,
          following: user_id,
        },
      });
    }
    setFollow(!fololow);
  };
  return (
    <div className='wall-user'>
      <header className='wall-info-user'>
        <div className='user-info'>
          <div className='image'>
            <Avatar
              alt='Remy Sharp'
              src={avatar}
              sx={{ width: 150, height: 150 }}
            />
          </div>

          <div className='detail'>
            <div className='user'>
              <h1 className='user-name'>{user_id}</h1>
              {fololow ? (
                <button
                  className='btn-follow'
                  onClick={sendFollow}>
                  Following
                  <ExpandMoreIcon></ExpandMoreIcon>
                </button>
              ) : (
                <button
                  className='btn-follow'
                  onClick={sendFollow}
                  style={{ backgroundColor: "rgba(0,149,246,1)" }}>
                  Follow
                  <ExpandMoreIcon></ExpandMoreIcon>
                </button>
              )}
              <button className='btn-message'>Message</button>
            </div>
            <div className='statics'>
              <ul>
                <li>
                  <span className='statics-count'>{postCount}</span> posts
                </li>
                <li>
                  <span className='statics-follower'>{followerCount}</span>{" "}
                  followers
                </li>
                <li>
                  <span className='statics-following'>{followingCount}</span>{" "}
                  following
                </li>
              </ul>
            </div>
          </div>
        </div>
      </header>
      {listFeed.map((feed, index) => (
        <Feed
          key={index}
          value={{ feed }}></Feed>
      ))}
    </div>
  );
};

export default WallUser;
