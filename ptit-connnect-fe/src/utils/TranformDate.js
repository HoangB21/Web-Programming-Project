const formatDate = (data) => {
  const date = new Date(data);

  const year = date.getFullYear();
  const month = ("0" + (date.getMonth() + 1)).slice(-2); // Thêm '0' vào trước số tháng và lấy hai chữ số cuối cùng
  const day = ("0" + date.getDate()).slice(-2); // Thêm '0' vào trước số ngày và lấy hai chữ số cuối cùng

  const formattedDate = `${year}-${month}-${day}`;

  return formattedDate;
};

export default formatDate;
