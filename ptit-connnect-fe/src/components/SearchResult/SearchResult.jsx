import { Avatar } from "@mui/material";
import axios from "axios";
import { Buffer } from "buffer";
import React, { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import "./SearchResult.scss";
//
import CircleIcon from "@mui/icons-material/Circle";

const SearchResult = (props) => {
  const { profile_name, name, image } = props.value;
  const [postCount, setPostCount] = useState(0);
  const [followerCount, setFollowerCount] = useState(0);
  const [followingCount, setFollowingCount] = useState(0);
  let src;
  const initWall = async () => {
    
    let response = await axios.get("http://localhost:9999/api/get-post-count", {
      params: {
        profile_name: profile_name,
      },
    });
    setPostCount(response.data);

    response = await axios.get("http://localhost:9999/api/get-follower-count", {
      params: {
        profile_name: profile_name,
      },
    });
    setFollowerCount(response.data);

    response = await axios.get(
      "http://localhost:9999/api/get-following-count",
      {
        params: {
          profile_name: profile_name,
        },
      }
    );
    setFollowingCount(response.data);
  };
  useEffect(() => {
    initWall();
  }, []);
  if (image !== null) {
    src = Buffer.from(image.data, "base64").toString("binary");
  } else {
    src =
      "https://static.vecteezy.com/system/resources/previews/000/352/070/original/vector-male-student-icon.jpg";
  }
  return (
    <Link
      className='search_result_item'
      to={`/wall/${profile_name}`}>
      <div className='owner'>
        <Avatar
          sx={{ width: 40, height: 40 }}
          src={src}
        />
        <div className='profile'>
          <span className='profile_name'>{profile_name}</span>

          <div className='type'>
            <span className='name'>{name}</span>
            {followerCount > 0 ? (
              <>
                <CircleIcon />
                <span>{followerCount} followers</span>
              </>
            ) : null}
          </div>
        </div>
      </div>
    </Link>
  );
};

export default SearchResult;
