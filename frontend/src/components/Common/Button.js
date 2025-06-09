import React from 'react';

const Button = ({
  children,
  type = 'button',
  variant = 'primary',
  size = 'medium',
  disabled = false,
  loading = false,
  onClick,
  className = '',
  ...props
}) => {
  const baseClasses = 'btn';
  const variantClasses = `btn-${variant}`;
  const sizeClasses = `btn-${size}`;
  const stateClasses = [
    disabled && 'btn-disabled',
    loading && 'btn-loading',
  ].filter(Boolean).join(' ');

  const allClasses = [
    baseClasses,
    variantClasses,
    sizeClasses,
    stateClasses,
    className,
  ].filter(Boolean).join(' ');

  return (
    <button
      type={type}
      className={allClasses}
      disabled={disabled || loading}
      onClick={onClick}
      {...props}
    >
      {loading && <span className="btn-spinner"></span>}
      <span className={loading ? 'btn-text-loading' : 'btn-text'}>
        {children}
      </span>
    </button>
  );
};

export default Button;
