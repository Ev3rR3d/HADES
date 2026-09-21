export default function HadesLogo({ size = 32, className = '' }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 32 32"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={className}
    >
      {/* Outer hexagon shield */}
      <path
        d="M16 1.5L29 8.75v14.5L16 30.5 3 23.25V8.75L16 1.5z"
        stroke="currentColor"
        strokeWidth="1.2"
        strokeLinejoin="round"
        opacity="0.3"
      />

      {/* Inner bident — two prongs converging to a point, reads as "H" */}
      {/* Left prong */}
      <path
        d="M10 7v13.5L16 26"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      {/* Right prong */}
      <path
        d="M22 7v13.5L16 26"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      {/* Crossbar */}
      <path
        d="M10 15h12"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinecap="round"
      />

      {/* Top prong tips — bident fork detail */}
      <path
        d="M8 9l2-2M12 9l-2-2M20 9l2-2M24 9l-2-2"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
      />
    </svg>
  );
}
