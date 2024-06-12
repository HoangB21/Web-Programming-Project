import React, { useState } from "react";
import Post from "../Post/Post";
import "./MessageSender.scss";
// Component
import Modal from "@mui/material/Modal";
import Avatar from "@mui/material/Avatar";

// Icon
import VideoCameraFrontIcon from "@mui/icons-material/VideoCameraFront";
import ImageIcon from "@mui/icons-material/Image";
import EmojiEmotionsIcon from "@mui/icons-material/EmojiEmotions";
//
import { pink, green, yellow } from "@mui/material/colors";
import axios from "axios";
import { Buffer } from "buffer";

const MessageSender = () => {
  const [currentUser, setCurrentUser] = useState(
    JSON.parse(localStorage.getItem("user"))
  );
  const [open, setOpen] = useState(false);
  const handleOpen = () => setOpen(true);
  const handleClose = () => setOpen(false);

  const [caption, setCaption] = useState("");
  const [images, setImages] = useState([]);
  const handleCaptionChange = (event) => {
    setCaption(event.target.value);
  };
  const haneleSubmit = async () => {
    try {
      await axios.post("http://localhost:9999/api/create-post", {
        userid: currentUser.user_id,
        content: caption,
        media: images,
      });
      handleClose();
      setCaption("");
      setImages([]);
      window.location.reload();
    } catch (error) {}
  };
  return (
    <div className='messageSender'>
      <div className='messageSender__top'>
        <Avatar
          sx={{ width: 40, height: 40 }}
          src={Buffer.from(currentUser.image.data, "base64").toString("binary")}
        />
        <form>
          <input
            value={caption}
            type='text'
            className='messageSender__input'
            placeholder="What's on your mind"
            onChange={() => {}}
            onClick={handleOpen}
          />
        </form>
        <Modal
          open={open}
          onClose={handleClose}>
          <Post
            defaultValue={{
              handleClose,
              handleCaptionChange,
              caption,
              images,
              setImages,
              haneleSubmit,
              currentUser,
            }}></Post>
        </Modal>
      </div>
      <div className='messageSender__bottom'>
        <div className='messageSender__option'>
          <VideoCameraFrontIcon
            sx={{ color: pink[600] }}></VideoCameraFrontIcon>
          <h3>Live Video</h3>
        </div>
        <div className='messageSender__option'>
          <ImageIcon sx={{ color: green[600] }}></ImageIcon>
          <h3>Photo/Video</h3>
        </div>
        <div className='messageSender__option'>
          <EmojiEmotionsIcon sx={{ color: yellow[600] }}></EmojiEmotionsIcon>
          <h3>Feeling/Activity</h3>
        </div>
      </div>
    </div>
  );
};

export default MessageSender;
