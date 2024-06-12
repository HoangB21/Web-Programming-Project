const bufferToBase64 = (data) => {
  const base64Flag = "data:image/jpeg;base64,";
  let binary = "";
  const bytes = [].slice.call(new Uint8Array(data));
  bytes.forEach((b) => (binary += String.fromCharCode(b)));
  return base64Flag + window.btoa(binary).replace("dataimage/jpegbase64", "");
};

export default bufferToBase64;
