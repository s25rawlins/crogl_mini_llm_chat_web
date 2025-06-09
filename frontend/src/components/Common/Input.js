import React from 'react';

const Input = ({
  type = 'text',
  placeholder = '',
  value = '',
  onChange,
  disabled = false,
  error = false,
  className = '',
  ...props
}) => {
  const baseClasses = 'input';
  const stateClasses = [
    disabled && 'input-disabled',
    error && 'input-error',
  ].filter(Boolean).join(' ');

  const allClasses = [
    baseClasses,
    stateClasses,
    className,
  ].filter(Boolean).join(' ');

  return (
    <input
      type={type}
      placeholder={placeholder}
      value={value}
      onChange={onChange}
      disabled={disabled}
      className={allClasses}
      {...props}
    />
  );
};

export default Input;
