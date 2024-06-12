import { Autocomplete, Avatar, Grid } from "@mui/material";
import Box from "@mui/material/Box";
import Button from "@mui/material/Button";
import TextField from "@mui/material/TextField";
import Typography from "@mui/material/Typography";
import React, { useEffect, useRef, useState } from "react";
import { useForm } from "react-hook-form";

import { Buffer } from "buffer";
import formatDate from "../../utils/TranformDate";
import "./Profile.scss";
import Modal from "@mui/material/Modal";

import axios from "axios";
const Profile = () => {
  const style = {
    position: "absolute",
    top: "50%",
    left: "50%",
    transform: "translate(-50%, -50%)",
    width: 400,
    bgcolor: "background.paper",
    border: "2px solid #000",
    boxShadow: 24,
    p: 4,
  };
  const [currentUser, setCurrentUser] = useState(
    JSON.parse(localStorage.getItem("user"))
  );
  const fileInputRef = useRef(null);
  const options = [{ label: "male" }, { label: "female" }];
  const [avatar, setAvatar] = useState("");
  const [open, setOpen] = useState(false);
  const [errorMessage, setErrorMessage] = useState("");

  const handleOpen = () => setOpen(true);
  const handleClose = () => setOpen(false);

  const {
    register,
    handleSubmit,
    formState: { errors },
    setValue,
    getValues,
  } = useForm();
  useEffect(() => {
    setValue("name", currentUser.name);
    setValue("profile_name", currentUser.profile_name);
    setValue("gender", currentUser.gender);
    // setValue("password", currentUser.password);
    setValue("dob", formatDate(currentUser.dob));
    if (currentUser.image) {
      setValue(
        "image",
        Buffer.from(currentUser.image.data, "base64").toString("binary")
      );
      setAvatar(
        Buffer.from(currentUser.image.data, "base64").toString("binary")
      );
      console.log(
        Buffer.from(currentUser.image.data, "base64").toString("binary")
      );
    }
    console.log(avatar);
  }, []);

  const onSubmit = async (data) => {
    console.log(data);
    if (data.newPassword !== data.confirm_new_password) {
      setErrorMessage("Incorrect confirm password");
      handleOpen();
    } else {
      try {
        const user = JSON.parse(localStorage.getItem("user"));
        await axios.put("http://localhost:9999/api/update-user", {
          ...user,
          ...data,
        });
        const response = await axios.get("http://localhost:9999/api/get-user", {
          params: {
            id: currentUser.user_id,
          },
        });
        localStorage.setItem(
          "user",
          JSON.stringify({
            ...response.data.user,
            password: currentUser.password,
          })
        );
        setCurrentUser({
          ...response.data.user,
          password: currentUser.password,
        });
      } catch (error) {}
    }
  };
  const handleImageUpload = (event) => {
    const selectedImage = event.target.files[0];
    if (selectedImage) {
      const reader = new FileReader();
      reader.onload = () => {
        const base64Image = reader.result;
        setAvatar(base64Image);
        setValue("image", base64Image);
      };
      reader.readAsDataURL(selectedImage);
    }
  };

  const handleButtonClick = (event) => {
    event.stopPropagation(); // Ngăn sự kiện nổi bọt
    event.preventDefault(); // Ngăn sự kiện mặc định của nút submit
    fileInputRef.current.click();
  };
  return (
    <div className='wrapper-profile'>
      <Modal
        open={open}
        onClose={handleClose}
        aria-labelledby='modal-modal-title'
        aria-describedby='modal-modal-description'>
        <Box sx={style}>
          <Typography
            id='modal-modal-title'
            variant='h6'
            component='h2'>
            Fail
          </Typography>
          <Typography
            id='modal-modal-description'
            sx={{ mt: 2 }}>
            {errorMessage}
          </Typography>
        </Box>
      </Modal>
      <div className='profile'>
        <Box
          className='form-register'
          component='form'
          onSubmit={handleSubmit(onSubmit)}
          sx={{
            width: "60%",
            height: "60%",
            margin: "auto",
            padding: "20px",
            borderRadius: "8px",
            boxShadow: "0 4px 8px rgba(0,0,0,0.1)",
            backgroundColor: "white",
          }}>
          <Typography
            style={{
              textAlign: "center",
              fontSize: "2rem",
              fontWeight: "500",
            }}
            variant='h5'
            component='div'>
            Profile
          </Typography>
          <Grid
            container
            spacing={3}>
            <Grid
              item
              xs={6}>
              <Grid
                container
                spacing={2}
                mt={1}>
                <Grid
                  item
                  xs={12}
                  mt={1}>
                  <TextField
                    fullWidth
                    InputLabelProps={{ shrink: true }}
                    label='Name'
                    {...register("name", {
                      required: "Name is required",
                      minLength: {
                        value: 3,
                        message: "Name must be at least 3 characters",
                      },
                    })}
                    error={Boolean(errors.name)}
                    helperText={errors.name?.message}
                  />
                </Grid>
                <Grid
                  item
                  xs={12}
                  mt={1}>
                  <TextField
                    fullWidth
                    InputLabelProps={{ shrink: true }}
                    label='Profile name'
                    {...register("profile_name", {
                      required: "Profile name is required",
                      minLength: {
                        value: 8,
                        message: "Profile name must be at least 8 characters",
                      },
                    })}
                    error={Boolean(errors.profile_name)}
                    helperText={errors.profile_name?.message}
                  />
                </Grid>
                <Grid
                  item
                  xs={12}
                  mt={1}>
                  <TextField
                    fullWidth
                    InputLabelProps={{ shrink: true }}
                    type='date'
                    label='Date of birth'
                    {...register("dob", {
                      required: "Date is required",
                    })}
                    error={Boolean(errors.dob)}
                    helperText={errors.dob?.message}
                  />
                </Grid>
                <Grid
                  item
                  xs={12}
                  mt={1}>
                  <Autocomplete
                    id='gender'
                    name='gender'
                    options={options}
                    sx={{ width: "100%" }}
                    getOptionLabel={(option) => option.label}
                    isOptionEqualToValue={(option, value) =>
                      option.label === value.label
                    }
                    defaultValue={
                      getValues("gender") === "male" ? options[1] : options[0]
                    }
                    onChange={(event, value) =>
                      setValue("gender", value?.label || "")
                    }
                    renderInput={(params) => (
                      <TextField
                        {...params}
                        label='Gender'
                        fullWidth
                        {...register("gender")}
                        //
                      />
                    )}
                  />
                </Grid>
                <Grid
                  item
                  xs={12}
                  mt={1}>
                  <TextField
                    fullWidth
                    type='password'
                    InputLabelProps={{ shrink: true }}
                    label='Current password'
                    {...register("password", {
                      required: "Password is required",
                      minLength: {
                        value: 8,
                        message: "Password must be at least 8 characters",
                      },
                    })}
                    error={Boolean(errors.profile_name)}
                    helperText={errors.profile_name?.message}
                  />
                </Grid>
                <Grid
                  item
                  xs={12}
                  mt={1}>
                  <TextField
                    fullWidth
                    type='password'
                    InputLabelProps={{ shrink: true }}
                    label='New password'
                    {...register("newPassword", {
                      required: "Password is required",
                      minLength: {
                        value: 8,
                        message: "Passwoed must be at least 8 characters",
                      },
                    })}
                    error={Boolean(errors.profile_name)}
                    helperText={errors.profile_name?.message}
                  />
                </Grid>
                <Grid
                  item
                  xs={12}
                  mt={1}>
                  <TextField
                    fullWidth
                    type='password'
                    InputLabelProps={{ shrink: true }}
                    label='Confirm new password'
                    {...register("confirm_new_password", {
                      required: "Confirm password is required",
                      minLength: {
                        value: 8,
                        message: "Confirm password is not match",
                      },
                    })}
                    error={Boolean(errors.profile_name)}
                    helperText={errors.profile_name?.message}
                  />
                </Grid>
              </Grid>
            </Grid>
            <Grid
              item
              xs={6}>
              <div className='upload-image'>
                <Avatar
                  alt='Remy Sharp'
                  src={avatar}
                  sx={{ width: 300, height: 300 }}
                />
                <input
                  {...register("image")}
                  type='file'
                  accept='image/*'
                  ref={fileInputRef}
                  onChange={handleImageUpload}
                />
                <button onClick={handleButtonClick}>Change avatar</button>
              </div>
            </Grid>
          </Grid>

          <Button
            type='submit'
            variant='contained'
            color='primary'
            fullWidth
            sx={{ mt: 1 }}>
            Update profile
          </Button>
        </Box>
      </div>
    </div>
  );
};

export default Profile;
