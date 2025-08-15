import React from "react";
import { FcGoogle } from "react-icons/fc";
// import { FaFacebook, FaTwitter, FaGithub } from "react-icons/fa";

const SocialLogin = () => {
  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        <div className="flex-grow h-px bg-gray-600"></div>
        <span className="text-sm text-gray-400">or</span>
        <div className="flex-grow h-px bg-gray-600"></div>
      </div>

      <button className="w-full flex items-center justify-center gap-3 border border-gray-600 rounded-md py-2 hover:bg-white/10 transition">
        <FcGoogle size={20} />
        <span className="text-sm font-medium">Login with Google</span>
      </button>

      {/* <div className="flex justify-center gap-6 text-xl mt-2">
        <FaFacebook className="cursor-pointer text-blue-500 hover:scale-110 transition" />
        <FaTwitter className="cursor-pointer text-sky-400 hover:scale-110 transition" />
        <FaGithub className="cursor-pointer text-gray-300 hover:scale-110 transition" />
      </div> */}
    </div>
  );
};

export default SocialLogin;
