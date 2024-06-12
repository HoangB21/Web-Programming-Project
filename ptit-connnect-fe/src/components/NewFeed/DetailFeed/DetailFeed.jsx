import React, { useEffect, useRef, useState } from "react";
import "swiper/css";
import "swiper/css/navigation";
import "swiper/css/pagination";
import "swiper/css/scrollbar";
import { A11y, Navigation, Pagination, Scrollbar } from "swiper/modules";
import { Swiper, SwiperSlide } from "swiper/react";
import "swiper/swiper-bundle.css";
import "./DetailFeed.scss";
// Library
import TextareaAutosize from "react-textarea-autosize"; // Assuming you are using a library like this

// Icon
import ClearIcon from "@mui/icons-material/Clear";
import FavoriteBorderIcon from "@mui/icons-material/FavoriteBorder";
import FavoriteIcon from "@mui/icons-material/Favorite";
import MoreHorizIcon from "@mui/icons-material/MoreHoriz";
import NavigateBeforeIcon from "@mui/icons-material/NavigateBefore";
import NavigateNextIcon from "@mui/icons-material/NavigateNext";
import SendIcon from "@mui/icons-material/Send";
import TelegramIcon from "@mui/icons-material/Telegram";
import TurnedInNotIcon from "@mui/icons-material/TurnedInNot";
import WebAssetIcon from "@mui/icons-material/WebAsset";
import { Avatar } from "@mui/material";
import axios from "axios";
// Library
import ReadMoreAndLess from "react-read-more-less";

const DetailFeed = React.forwardRef((props, ref) => {
  const {
    handleClose,
    feed,
    comment,
    handleCommentChange,
    sendComment,
    reacted,
    sendReact,
  } = props.value;
  const [comments, setComments] = useState([]);
  const swipperRef = useRef(null);
  const getComments = async () => {
    try {
      const response = await axios.get(
        "http://localhost:9999/api/get-comment-by-post",
        {
          params: {
            postId: feed.post_id,
          },
        }
      );
      setComments([...response.data]);
    } catch (error) {}
  };
  const handleComment = async () => {
    await sendComment();
    await getComments();
  };
  useEffect(() => {
    getComments();
  }, []);
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
    <div className='detail-feed'>
      <ClearIcon
        onClick={handleClose}
        className='btn-close'></ClearIcon>
      <div className='wrapper'>
        <div className='slider'>
          <Swiper
            ref={swipperRef}
            modules={[Navigation, Pagination, Scrollbar, A11y]}
            spaceBetween={50}
            pagination={{ clickable: true }}
            scrollbar={{ draggable: true }}
            slidesPerView={1}
            effect='slide'>
            {feed.media.map((image, index) => (
              <SwiperSlide key={index}>
                <div className='box-image'>
                  <img
                    src={image.file_content?.data}
                    alt=''
                  />
                  <div className='btn-pagination'>
                    <NavigateBeforeIcon
                      onClick={handlePrevImages}
                      className={
                        index ? "btn-prev" : "disable"
                      }></NavigateBeforeIcon>
                    <NavigateNextIcon
                      onClick={handleNextImages}
                      className={
                        index !== feed.media.length - 1 ? "btn-next" : "disable"
                      }></NavigateNextIcon>
                  </div>
                </div>
              </SwiperSlide>
            ))}
          </Swiper>
        </div>
        <div className='detail'>
          <div className='owner'>
            <Avatar
              sx={{ width: 40, height: 40 }}
              src={feed.image}
            />
            <div className='detail_feed'>
              <div style={{ display: "flex", height: "min-content" }}>
                <div className='profile'>
                  <h3>{feed.author}</h3>
                </div>

                <div className='more'>
                  <MoreHorizIcon></MoreHorizIcon>
                  {/* <ClearIcon></ClearIcon> */}
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
            </div>
          </div>

          <div className='comment'>
            {comments.map((comment, index) => (
              <div
                className='caption'
                key={index}>
                <Avatar
                  sx={{ width: 40, height: 40 }}
                  src={comment.avatar}
                />
                <div className='profile'>
                  <h3>{comment.owner}</h3>
                  <div className='type'>
                    <span>{comment.content}</span>
                  </div>
                </div>
              </div>
            ))}
          </div>
          <div className='static'>
            {reacted ? (
              <FavoriteIcon
                onClick={sendReact}
                style={{ color: "rgb(255, 48, 65)" }}
              />
            ) : (
              <FavoriteBorderIcon onClick={sendReact} />
            )}
            <WebAssetIcon></WebAssetIcon>
            <TelegramIcon></TelegramIcon>
            <TurnedInNotIcon></TurnedInNotIcon>
          </div>
          <p className='time'>{feed.createdAt}</p>
          <div className='footer'>
            <div className='your-comment'>
              <TextareaAutosize
                style={{
                  resize: "none",
                  fontSize: "1.6rem",
                  width: "100%",
                  outline: "none",
                  border: "none",
                  background: "transparent",
                  fontFamily: "inherit",
                  height: "100% !important",
                }}
                className='comment_input'
                aria-label='empty textarea'
                placeholder='Add your comment'
                value={comment}
                onChange={(event) => handleCommentChange(event.target.value)}
              />
              <SendIcon
                onClick={handleComment}
                style={comment.length ? { color: "#57b5de" } : {}}></SendIcon>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
});

export default DetailFeed;
