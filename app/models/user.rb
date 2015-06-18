class User < ActiveRecord::Base
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable and :omniauthable
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :trackable, :validatable, :confirmable, :lockable, :zxcvbnable
  
  def send_devise_notification(notification, *args)
	  if Rails.env.production?
		  device_mailer.send(notification, self, *args).deliver_now
	  else
		  devise_mailer.send(notification, self, *args).deliver_later
	  end
  end
end
