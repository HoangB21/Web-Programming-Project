import React, { useState } from "react";
import "./SearchBox.scss";
import TextField from "@mui/material/TextField";
import Autocomplete from "@mui/material/Autocomplete";
import Paper from "@mui/material/Paper";
import { createTheme, ThemeProvider } from "@mui/material/styles";
import axios from "axios";
import SearchResult from "../SearchResult/SearchResult";

const SearchBox = () => {
  const [inputValue, setInputValue] = useState("");
  const [options, setOptions] = useState([]);

  const handleInputChange = async (event, newInputValue) => {
    setInputValue(newInputValue);
    try {
      const response = await axios.get(
        "http://localhost:9999/api/search-user",
        {
          params: {
            keyword: newInputValue,
          },
        }
      );
      setOptions(response.data);
    } catch (error) {
      console.error("Error fetching data:", error);
    }
  };

  const theme = createTheme({
    components: {
      MuiAutocomplete: {
        styleOverrides: {
          noOptions: {
            color: "white",
            backgroundColor: "#18191a",
          },
        },
      },
    },
  });

  return (
    <div className='box_search'>
      <ThemeProvider theme={theme}>
        <Autocomplete
          inputValue={inputValue}
          onInputChange={handleInputChange}
          options={options}
          getOptionLabel={(option) => option.profile_name || ""}
          id='combo-box-demo'
          className='search_input'
          sx={{
            width: 300,
            zIndex: 99,
            borderRadius: "0.5rem",
            boxShadow: "0px 4px 6px rgba(0, 0, 0, 0.1)",
          }}
          PaperComponent={({ children }) => (
            <Paper
              className='search_result_paper'
              style={{
                backgroundColor: "#18191a",
                color: "white",
              }}>
              {children}
            </Paper>
          )}
          renderInput={(params) => (
            <TextField
              {...params}
              label='Search'
              InputLabelProps={{
                className: "customInputLabel",
                style: {
                  color: "white",
                  fontSize: "1.2rem",
                },
              }}
              InputProps={{
                ...params.InputProps,
                className: "customInput",
                style: {
                  color: "white",
                  borderBottomColor: "white",
                },
              }}
            />
          )}
          renderOption={(props, option) => (
            <div
              {...props}
              style={{
                zIndex: 9999,
                padding: 0,
              }}>
              <SearchResult value={option}></SearchResult>
            </div>
          )}
          noOptionsText='Không tìm thấy kết quả'
        />
      </ThemeProvider>
    </div>
  );
};

export default SearchBox;
