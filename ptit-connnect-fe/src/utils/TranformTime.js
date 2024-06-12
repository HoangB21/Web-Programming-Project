const comparePostTime = (postDateTimeString) => {
  // const postDateTime = new Date(postDateTimeString);

  // // Lấy múi giờ của máy tính client
  // const clientTimezoneOffset = new Date().getTimezoneOffset() * 60000; // Đổi sang mili giây
  // // Chuyển đổi thời gian từ UTC sang múi giờ của máy tính client
  // const localPostDateTime = new Date(
  //   postDateTime.getTime() + clientTimezoneOffset
  // );

  // const currentDateTime = new Date();

  // const elapsedMilliseconds = currentDateTime - localPostDateTime;
  // const elapsedSeconds = Math.floor(elapsedMilliseconds / 1000);
  // const elapsedMinutes = Math.floor(elapsedSeconds / 60);
  // const elapsedHours = Math.floor(elapsedMinutes / 60);
  // const elapsedDays = Math.floor(elapsedHours / 24);

  // if (elapsedDays > 7) {
  //   return localPostDateTime.toLocaleDateString("en-US", {
  //     year: "numeric",
  //     month: "short",
  //     day: "numeric",
  //   });
  // } else if (elapsedDays >= 1) {
  //   return `${elapsedDays} day${elapsedDays > 1 ? "s" : ""} ago`;
  // } else if (elapsedHours >= 1) {
  //   return `${elapsedHours} hour${elapsedHours > 1 ? "s" : ""} ago`;
  // } else if (elapsedMinutes >= 1) {
  //   return `${elapsedMinutes} minute${elapsedMinutes > 1 ? "s" : ""} ago`;
  // } else if (elapsedSeconds >= 1) {
  //   return `${elapsedSeconds} second${elapsedSeconds > 1 ? "s" : ""} ago`;
  // } else {
  //   return "Just now";
  // }
  const postDateTime = new Date(postDateTimeString);
  const currentDateTime = new Date();

  const elapsedMilliseconds = currentDateTime - postDateTime;
  const elapsedSeconds = Math.floor(elapsedMilliseconds / 1000);
  const elapsedMinutes = Math.floor(elapsedSeconds / 60);
  const elapsedHours = Math.floor(elapsedMinutes / 60);
  const elapsedDays = Math.floor(elapsedHours / 24);

  if (elapsedDays > 0) {
    return `${elapsedDays}d`;
  } else if (elapsedHours > 0) {
    return `${elapsedHours}h`;
  } else if (elapsedMinutes > 0) {
    return `${elapsedMinutes}m`;
  } else {
    return `${elapsedSeconds}s`;
  }
};

export default comparePostTime;
