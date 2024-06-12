import React from "react";
import "swiper/css";
import "swiper/css/navigation";
import "swiper/swiper-bundle.css";
import "./Post.scss";
// Icon
import AddLocationAltIcon from "@mui/icons-material/AddLocationAlt";
import CancelIcon from "@mui/icons-material/Cancel";
import CollectionsIcon from "@mui/icons-material/Collections";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import GifIcon from "@mui/icons-material/Gif";
import InsertEmoticonIcon from "@mui/icons-material/InsertEmoticon";
import MoreHorizIcon from "@mui/icons-material/MoreHoriz";
import PublicIcon from "@mui/icons-material/Public";
import StyleIcon from "@mui/icons-material/Style";
import Tooltip, { tooltipClasses } from "@mui/material/Tooltip";

import { styled } from "@mui/material/styles";

// Component
import Avatar from "@mui/material/Avatar";
import TextareaAutosize from "react-textarea-autosize"; // Assuming you are using a library like this
// Library
import { A11y, Navigation } from "swiper/modules";
import { Swiper, SwiperSlide } from "swiper/react";
import { Buffer } from "buffer";

const LightTooltip = styled(({ className, ...props }) => (
  <Tooltip
    {...props}
    classes={{ popper: className }}
  />
))(({ theme }) => ({
  [`& .${tooltipClasses.tooltip}`]: {
    backgroundColor: theme.palette.common.gray,
    color: "white",
    padding: "1rem",
    boxShadow: theme.shadows[1],
    fontSize: 14,
  },
}));

const Post = React.forwardRef((props, ref) => {
  const {
    handleClose,
    handleCaptionChange,
    caption,
    images,
    setImages,
    haneleSubmit,
    currentUser,
  } = props.defaultValue;

  const handleImageUpload = (event) => {
    const selectedImage = event.target.files[0];
    if (selectedImage) {
      const reader = new FileReader();
      reader.onload = () => {
        const base64Image = reader.result;
        setImages((images) => [...images, base64Image]);
      };
      reader.readAsDataURL(selectedImage);
    }
  };
  const handleImageDelete = (index) => {
    const updatedImages = [...images];
    updatedImages.splice(index, 1);
    setImages(updatedImages);
  };
  return (
    <div className='post'>
      <div className='wrapper'>
        <div className='header'>
          <div className='title'>Tạo bài viết</div>
          <CancelIcon onClick={handleClose}></CancelIcon>
        </div>
        <div className='body'>
          <div className='owner'>
            <Avatar
              sx={{ width: 56, height: 56 }}
              src={Buffer.from(currentUser.image.data, "base64").toString(
                "binary"
              )}
            />
            <div className='profile'>
              <h3>{currentUser.name}</h3>
              <div className='type'>
                <PublicIcon></PublicIcon>
                <span>Public</span>
                <ExpandMoreIcon></ExpandMoreIcon>
              </div>
            </div>
          </div>

          <TextareaAutosize
            style={{
              resize: "none",
              fontSize: "2rem",
              width: "100%",
              marginTop: "2rem",
              outline: "none",
              border: "none",
              background: "transparent",
              color: "white",
              fontFamily: "inherit",
            }}
            aria-label='empty textarea'
            placeholder='Sharing your mind'
            value={caption}
            onChange={handleCaptionChange}
          />
          <div className='slider'>
            <Swiper
              modules={[Navigation, A11y]}
              spaceBetween={50}
              slidesPerView={1}
              navigation={true}
              pagination={{ clickable: true }}
              scrollbar={{ draggable: true }}>
              {images.map((image, index) => (
                <SwiperSlide key={index}>
                  <div className='box-image'>
                    <img
                      src={image}
                      alt=''
                    />
                    <CancelIcon
                      className='icon-cancle'
                      onClick={() => handleImageDelete(index)}></CancelIcon>
                  </div>
                </SwiperSlide>
              ))}
            </Swiper>
          </div>

          <div className='custom'>
            <span>Add to your post</span>
            <div className='btn-custom'>
              <LightTooltip
                title='Photo/video'
                placement='top'>
                <div className='icon'>
                  <label htmlFor='image'>
                    <CollectionsIcon
                      style={{
                        color: "rgb(46, 202, 46)",
                      }}></CollectionsIcon>
                  </label>
                  <input
                    type='file'
                    id='image'
                    name='img'
                    accept='image/jpeg'
                    onChange={handleImageUpload}
                    style={{ display: "none" }}
                  />
                </div>
              </LightTooltip>

              <LightTooltip
                title='Tag people'
                placement='top'>
                <div className='icon'>
                  <StyleIcon
                    style={{
                      color: "rgb(119, 146, 224)",
                    }}></StyleIcon>
                </div>
              </LightTooltip>
              <LightTooltip
                title='Feeling/activity'
                placement='top'>
                <div className='icon'>
                  <InsertEmoticonIcon
                    style={{
                      color: "rgb(174, 235, 53)",
                    }}></InsertEmoticonIcon>
                </div>
              </LightTooltip>
              <LightTooltip
                title='Check in'
                placement='top'>
                <div className='icon'>
                  <AddLocationAltIcon
                    style={{
                      color: "rgb(244, 66, 66)",
                    }}></AddLocationAltIcon>
                </div>
              </LightTooltip>
              <LightTooltip
                title='GIF'
                placement='top'>
                <div className='icon'>
                  <GifIcon
                    style={{
                      color: "rgb(45, 227, 215)",
                    }}></GifIcon>
                </div>
              </LightTooltip>
              <LightTooltip
                title='More'
                placement='top'>
                <div className='icon'>
                  <MoreHorizIcon></MoreHorizIcon>
                </div>
              </LightTooltip>
            </div>
          </div>
          <button
            onClick={haneleSubmit}
            className={
              caption.length || images.length
                ? "btn-submit"
                : "btn-submit disable"
            }>
            Post
          </button>
        </div>
      </div>
    </div>
  );
});

export default Post;
