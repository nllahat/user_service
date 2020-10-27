Rails.application.routes.draw do
  resources :users

  post '/sign_up', to: 'users#sign_up'
  post '/sign_in', to: 'users#sign_in'
  post '/sign_out', to: 'users#sign_out'
end
