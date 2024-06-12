import React, { useEffect, useRef, useState } from "react";
import "swiper/css";
import "swiper/css/navigation";
import "swiper/css/pagination";
import "swiper/css/scrollbar";
import "./Feed.scss";

import "swiper/swiper-bundle.css";
// Library
import ReadMoreAndLess from "react-read-more-less";
import TextareaAutosize from "react-textarea-autosize"; // Assuming you are using a library like this
import { A11y, Navigation, Pagination, Scrollbar } from "swiper/modules";
import { Swiper, SwiperSlide } from "swiper/react";

// Icon
import CircleIcon from "@mui/icons-material/Circle";
import ClearIcon from "@mui/icons-material/Clear";
import FavoriteBorderIcon from "@mui/icons-material/FavoriteBorder";
import FavoriteIcon from "@mui/icons-material/Favorite";
import MoreHorizIcon from "@mui/icons-material/MoreHoriz";
import NavigateBeforeIcon from "@mui/icons-material/NavigateBefore";
import NavigateNextIcon from "@mui/icons-material/NavigateNext";
import PublicIcon from "@mui/icons-material/Public";
import SendIcon from "@mui/icons-material/Send";
import TelegramIcon from "@mui/icons-material/Telegram";
import TurnedInNotIcon from "@mui/icons-material/TurnedInNot";
import WebAssetIcon from "@mui/icons-material/WebAsset";
import { Avatar } from "@mui/material";
import Modal from "@mui/material/Modal";
import axios from "axios";
import { debounce } from "lodash";
import DetailFeed from "../DetailFeed/DetailFeed";
import { Link } from "react-router-dom";

const Feed = (props) => {
  const { feed } = props.value;
  const swipperRef = useRef(null);
  const [comment, setComment] = useState("");
  const [open, setOpen] = useState(false);
  const [reacted, setReacted] = useState(false);
  const handleOpen = () => setOpen(true);
  const handleClose = () => setOpen(false);
  useEffect(() => {
    const user = JSON.parse(localStorage.getItem("user"));
    const checkReact = async () => {
      const response = await axios.get(
        "http://localhost:9999/api/check-reacted",
        {
          params: {
            user_id: user.user_id,
            post_id: feed.post_id,
          },
        }
      );
      setReacted(response.data);
      // console.log(response.data);
    };
    checkReact();
  }, []);
  const handleCommentChange = debounce((data) => {
    setComment(data);
  }, 20);
  const sendComment = async () => {
    try {
      const user = JSON.parse(localStorage.getItem("user"));
      await axios.post("http://localhost:9999/api/create-comment", {
        owner: user.user_id,
        post_id: feed.post_id,
        content: comment,
      });
      setComment("");
    } catch (error) {}
  };
  const sendReact = async () => {
    const user = JSON.parse(localStorage.getItem("user"));
    if (!reacted) {
      await axios.post("http://localhost:9999/api/react", {
        user_id: user.user_id,
        post_id: feed.post_id,
      });
    } else {
      await axios.delete("http://localhost:9999/api/undo-react", {
        params: {
          user_id: user.user_id,
          post_id: feed.post_id,
        },
      });
    }
    setReacted(!reacted);
  };
  const handlePrevImages = () => {
    if (swipperRef.current) {
      swipperRef.current.swiper.slidePrev(); // Go to the previous slide
    }
  };

  const handleNextImages = () => {
    if (swipperRef.current) {
      swipperRef.current.swiper.slideNext(); // Go to the next slide
    }
  };
  return (
    <div className='feed'>
      <div className='owner'>
        <Avatar
          sx={{ width: 40, height: 40 }}
          src={feed.image}
        />
        <div className='profile'>
          <Link to={`/wall/${feed.author}`}>{feed.author}</Link>

          <div className='type'>
            <span>{feed.createdAt}</span>
            <CircleIcon></CircleIcon>
            <PublicIcon></PublicIcon>
          </div>
        </div>
        <div className='more'>
          <MoreHorizIcon></MoreHorizIcon>
          <ClearIcon></ClearIcon>
        </div>
      </div>
      <div className='caption'>
        <ReadMoreAndLess
          charLimit={50}
          readMoreText='See more'
          readLessText=''
          readMoreClassName='read-more-content'
          readLessClassName='read-less-content'>
          {feed.content}
        </ReadMoreAndLess>
      </div>
      <div className='slider'>
        <Swiper
          ref={swipperRef}
          modules={[Navigation, Pagination, Scrollbar, A11y]}
          spaceBetween={0}
          pagination={{ clickable: true }}
          scrollbar={{ draggable: true }}
          slidesPerView={1}
          effect='slide'>
          {feed.media?.map((item, index) => (
            <SwiperSlide key={index}>
              <div className='box-image'>
                {item.file_content && (
                  <img
                    src={item.file_content.data}
                    alt=''
                  />
                )}
                <div className='btn-pagination'>
                  <NavigateBeforeIcon
                    onClick={handlePrevImages}
                    className={
                      index ? "btn-prev" : "disable"
                    }></NavigateBeforeIcon>
                  <NavigateNextIcon
                    onClick={handleNextImages}
                    className={
                      index !== feed.media?.length - 1 ? "btn-next" : "disable"
                    }></NavigateNextIcon>
                </div>
              </div>
            </SwiperSlide>
          ))}
        </Swiper>
      </div>
      <div className='static'>
        {reacted ? (
          <FavoriteIcon
            onClick={sendReact}
            style={{ color: "rgb(255, 48, 65)" }}
          />
        ) : (
          <FavoriteBorderIcon
            className='none_favourite_icon'
            onClick={sendReact}
          />
        )}

        <WebAssetIcon onClick={handleOpen}></WebAssetIcon>
        <Modal
          open={open}
          onClose={handleClose}>
          <DetailFeed
            value={{
              handleClose,
              feed: feed,
              comment,
              handleCommentChange,
              sendComment,
              reacted,
              sendReact,
            }}></DetailFeed>
        </Modal>
        <TelegramIcon></TelegramIcon>
        <TurnedInNotIcon></TurnedInNotIcon>
      </div>
      <div className='comment'>
        <TextareaAutosize
          style={{
            resize: "none",
            fontSize: "1.6rem",
            width: "100%",
            outline: "none",
            border: "none",
            background: "transparent",
            fontFamily: "inherit",
          }}
          className='comment_input'
          aria-label='empty textarea'
          placeholder='Add your comment'
          value={comment}
          onChange={(event) => handleCommentChange(event.target.value)}
        />
        <SendIcon
          onClick={sendComment}
          style={comment?.length ? { color: "#57b5de" } : {}}></SendIcon>
      </div>
    </div>
  );
};

export default Feed;
