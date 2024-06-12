import { Autocomplete, Grid } from "@mui/material";
import Box from "@mui/material/Box";
import Button from "@mui/material/Button";
import TextField from "@mui/material/TextField";
import Typography from "@mui/material/Typography";
import React, { useState } from "react";
import { useForm } from "react-hook-form";
import { Link, useNavigate } from "react-router-dom";

import axios from "axios";
import "./Register.scss";

export default function Register() {
  const navigate = useNavigate();
  const [errorLogin] = useState(false);
  const {
    register,
    handleSubmit,
    formState: { errors },
    setValue,
  } = useForm();
  const options = [{ label: "male" }, { label: "female" }];
  const onSubmit = async (data) => {
    data.role = "1";
    console.log(data);
    try {
      await axios.post("http://localhost:9999/api/create-user", {
        ...data,
      });
      navigate("/login");
    } catch (error) {
      console.log(error);
    }
  };

  return (
    <div className='wrapper-register'>
      <img
        src='https://res.cloudinary.com/dtxh1xgnb/image/upload/v1712641670/mwjfml0lqusd8wdvivcy.jpg'
        alt=''
      />
      <div className='register'>
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
            Sign up Form
          </Typography>
          <Grid
            container
            spacing={2}
            mt={1}>
            <Grid
              item
              xs={4}>
              <TextField
                fullWidth
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
              xs={6}>
              <TextField
                fullWidth
                type='date'
                label='Date of birth'
                InputLabelProps={{ shrink: true }}
                placeholder='YYYY-MM-DD' // Placeholder example
                {...register("dob", {
                  required: "Date of birth is required",
                })}
                error={Boolean(errors.dob)}
                helperText={errors.dob?.message}
              />
            </Grid>
            <Grid
              item
              xs={2}>
              <Autocomplete
                disablePortal
                id='gender'
                name='gender'
                options={options}
                sx={{ width: "100%" }}
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
              xs={4}
              mt={1}>
              <TextField
                fullWidth
                label='UserId'
                {...register("user_id", {
                  required: "UserId is required",
                })}
                error={Boolean(errors.user_id)}
                helperText={errors.userid?.message}
              />
            </Grid>
            <Grid
              item
              xs={4}
              mt={1}>
              <TextField
                fullWidth
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
              xs={4}
              mt={1}>
              <TextField
                fullWidth
                label='Email'
                {...register("email", {
                  required: "Profile name is required",
                })}
                error={Boolean(errors.email)}
                helperText={errors.email?.message}
              />
            </Grid>
            <Grid
              item
              xs={6}
              mt={1}>
              <TextField
                fullWidth
                type='password'
                label='Password'
                {...register("password", {
                  required: "Password is required",
                })}
                error={Boolean(errors.password)}
                helperText={errors.password?.message}
              />
            </Grid>
            <Grid
              item
              xs={6}
              mt={1}>
              <TextField
                fullWidth
                type='password'
                label='Confirm password'
                {...register("confirm_password", {
                  required: "Confirm password is required",
                })}
                error={Boolean(errors.confirm_password)}
                helperText={errors.confirm_password?.message}
              />
            </Grid>
          </Grid>

          <p className={errorLogin ? "error" : "disable"}>
            Tài khoản và mật khẩu không đúng
          </p>

          <Button
            type='submit'
            variant='contained'
            color='primary'
            fullWidth
            sx={{ mt: 1 }}>
            Register
          </Button>
          <Box sx={{ mt: 2, textAlign: "center" }}>
            <Box mt={1}>
              <Link to='/login'>Already have an account? Sign in</Link>
            </Box>
          </Box>
        </Box>
      </div>
    </div>
  );
}
