#include "rclcpp/rclcpp.hpp"
#include "std_msgs/msg/string.hpp"
#include "std_msgs/msg/float32.hpp"
#include <time.h>
#include <iostream>
#include <chrono>

#include <iostream>
#include <chrono>
#include <cstdlib> // for std::atoll


clock_t start;
clock_t end;

std::chrono::time_point<std::chrono::high_resolution_clock> start_cordoba, end_cordoba;

std::chrono::time_point<std::chrono::high_resolution_clock> start_lyon, end_lyon;

std::chrono::time_point<std::chrono::high_resolution_clock> start_hamburg, end_hamburg;
std::chrono::time_point<std::chrono::high_resolution_clock> start_osaka, end_osaka;
std::chrono::time_point<std::chrono::high_resolution_clock> start_tripoli, end_tripoli;
std::chrono::time_point<std::chrono::high_resolution_clock> start_mandalay, end_mandalay;
std::chrono::time_point<std::chrono::high_resolution_clock> start_ponce, end_ponce;
std::chrono::time_point<std::chrono::high_resolution_clock> start_barcelona, end_barcelona;
std::chrono::time_point<std::chrono::high_resolution_clock> start_georgetown, end_georgetown;

// Publisher Node
// class cordoba : public rclcpp::Node
// {
// public:
//     cordoba() : Node("cordoba")
//     {
//         publisher_ = this->create_publisher<std_msgs::msg::Float32>("amazon", 10);
//         auto message = std_msgs::msg::Float32();
//         message.data = 25.22;
//         // RCLCPP_INFO(this->get_logger(), "Publishing: '%f'", message.data);
//         start_cordoba = std::chrono::high_resolution_clock::now();

//         publisher_->publish(message);

//         timer_ = this->create_wall_timer(
//             std::chrono::seconds(1),
//             std::bind(&cordoba::timer_callback, this));
//     }

// private:
//     void timer_callback()
//     {
//         auto message = std_msgs::msg::Float32();
//         message.data = 25.22;
//         // start_cordoba = std::chrono::high_resolution_clock::now();
//         // RCLCPP_INFO(this->get_logger(), "Publishing: '%ld'", start_cordoba);
       
//                auto now = this->get_clock()->now();
//         auto now_us = now.nanoseconds() / 1000;

//         RCLCPP_INFO(
//             this->get_logger(),
//             "Current timestamp: %ld us",
//             now_us
//         );

//         publisher_->publish(message);
//     }

//     rclcpp::Publisher<std_msgs::msg::Float32>::SharedPtr publisher_;
//     rclcpp::TimerBase::SharedPtr timer_;
// };



#include <rclcpp/rclcpp.hpp>
#include <std_msgs/msg/byte_multi_array.hpp>

class cordoba : public rclcpp::Node
{
public:
    cordoba() : Node("cordoba")
    {
        publisher_ = this->create_publisher<std_msgs::msg::ByteMultiArray>("amazon", 10);


        timer_ = this->create_wall_timer(
            std::chrono::seconds(1),
            std::bind(&cordoba::timer_callback, this));
    }

private:
    void timer_callback()
    {
        std_msgs::msg::ByteMultiArray message;
        message.data.resize(1024*1024);  // 1 KB

        for (size_t i = 0; i < message.data.size(); ++i) {
            message.data[i] = static_cast<uint8_t>(i % 256);
        }

        auto now = this->get_clock()->now();
        auto now_us = now.nanoseconds() / 1000;

        RCLCPP_INFO(
            this->get_logger(),
            "Current timestamp: %ld us, payload size: %zu bytes",
            now_us,
            message.data.size()
        );

        publisher_->publish(message);
    }

    rclcpp::Publisher<std_msgs::msg::ByteMultiArray>::SharedPtr publisher_;
    rclcpp::TimerBase::SharedPtr timer_;
    std::chrono::high_resolution_clock::time_point start_cordoba;
};





class freeport : public rclcpp::Node
{
public:
    freeport() : Node("freeport")
    {
        publisher_ = this->create_publisher<std_msgs::msg::String>("ganges", 10);
        timer_ = this->create_wall_timer(
            std::chrono::seconds(1),
            std::bind(&freeport::timer_callback, this));
    }

private:
    void timer_callback()
    {
        auto message = std_msgs::msg::String();
        message.data = "Hello, ROS2!";
        // RCLCPP_INFO(this->get_logger(), "Publishing: '%s'", message.data.c_str());
        publisher_->publish(message);
    }

    rclcpp::Publisher<std_msgs::msg::String>::SharedPtr publisher_;
    rclcpp::TimerBase::SharedPtr timer_;
};

class medellin : public rclcpp::Node
{
public:
    medellin() : Node("medellin")
    {
        publisher_ = this->create_publisher<std_msgs::msg::String>("nile", 10);
        timer_ = this->create_wall_timer(
            std::chrono::seconds(1),
            std::bind(&medellin::timer_callback, this));
    }

private:
    void timer_callback()
    {
        auto message = std_msgs::msg::String();
        message.data = "Hello, ROS2!";
        // RCLCPP_INFO(this->get_logger(), "Publishing: '%s'", message.data.c_str());
        publisher_->publish(message);
    }

    rclcpp::Publisher<std_msgs::msg::String>::SharedPtr publisher_;
    rclcpp::TimerBase::SharedPtr timer_;
};

class portsmouth : public rclcpp::Node
{
public:
    portsmouth() : Node("portsmouth")
    {
        publisher_ = this->create_publisher<std_msgs::msg::String>("danube", 10);
        timer_ = this->create_wall_timer(
            std::chrono::seconds(1),
            std::bind(&portsmouth::timer_callback, this));
    }

private:
    void timer_callback()
    {
        auto message = std_msgs::msg::String();
        message.data = "Hello, ROS2!";
        // RCLCPP_INFO(this->get_logger(), "Publishing: '%s'", message.data.c_str());
        publisher_->publish(message);
    }

    rclcpp::Publisher<std_msgs::msg::String>::SharedPtr publisher_;
    rclcpp::TimerBase::SharedPtr timer_;
};

// class lyon : public rclcpp::Node
// {
// public:
//     lyon() : Node("lyon")
//     {
//         subscription_ = this->create_subscription<std_msgs::msg::Float32>(
//             "amazon", 10,
//             std::bind(&lyon::timer_callback, this, std::placeholders::_1));
//         publisher_ = this->create_publisher<std_msgs::msg::Float32>("tigris", 10);
//     }

// private:
//     void timer_callback(const std_msgs::msg::Float32::SharedPtr msg)
//     {
//         // start_lyon = std::chrono::high_resolution_clock::now();
//         // auto duration = std::chrono::duration_cast<std::chrono::microseconds>(start_lyon - start_cordoba);

//         // RCLCPP_INFO(this->get_logger(), "Message Reached here at %llu", duration.count());

//    auto now = this->get_clock()->now();
//         auto now_us = now.nanoseconds() / 1000;

//         RCLCPP_INFO(
//             this->get_logger(),
//             "Publishing at timestamp: %ld us",
//             now_us
//         );


//         publisher_->publish(*msg);
//     }

//     rclcpp::Publisher<std_msgs::msg::Float32>::SharedPtr publisher_;
//     rclcpp::Subscription<std_msgs::msg::Float32>::SharedPtr subscription_;
//     rclcpp::TimerBase::SharedPtr timer_;
// };

#include <rclcpp/rclcpp.hpp>
#include <std_msgs/msg/byte_multi_array.hpp>

class lyon : public rclcpp::Node
{
public:
    lyon() : Node("lyon")
    {
        subscription_ = this->create_subscription<std_msgs::msg::ByteMultiArray>(
            "amazon", 10,
            std::bind(&lyon::timer_callback, this, std::placeholders::_1));

        publisher_ = this->create_publisher<std_msgs::msg::ByteMultiArray>("tigris", 10);
    }

private:
    void timer_callback(const std_msgs::msg::ByteMultiArray::SharedPtr msg)
    {
        auto now = this->get_clock()->now();
        auto now_us = now.nanoseconds() / 1000;

        RCLCPP_INFO(
            this->get_logger(),
            "Publishing at timestamp: %ld us, payload size: %zu bytes",
            now_us,
            msg->data.size()
        );

        // Forward the same 1 KB payload
        publisher_->publish(*msg);
    }

    rclcpp::Publisher<std_msgs::msg::ByteMultiArray>::SharedPtr publisher_;
    rclcpp::Subscription<std_msgs::msg::ByteMultiArray>::SharedPtr subscription_;
};


// class hamburg : public rclcpp::Node
// {
// public:
//     hamburg() : Node("hamburg")
//     {
//         publisher1_ = this->create_publisher<std_msgs::msg::Float32>("parana", 10);

//         // timer1_ = this->create_wall_timer(10ms, std::bind(&hamburg::publish_topic1, this));
//         // Subscribers
//         subscriptionA_ = this->create_subscription<std_msgs::msg::String>(
//             "nile", 10, std::bind(&hamburg::topicA_callback, this, std::placeholders::_1));
//         subscriptionB_ = this->create_subscription<std_msgs::msg::Float32>(
//             "tigris", 10, std::bind(&hamburg::topicB_callback, this, std::placeholders::_1));
//         subscriptionC_ = this->create_subscription<std_msgs::msg::String>(
//             "ganges", 10, std::bind(&hamburg::topicC_callback, this, std::placeholders::_1));
//         subscriptionD_ = this->create_subscription<std_msgs::msg::String>(
//             "danube", 10, std::bind(&hamburg::topicD_callback, this, std::placeholders::_1));
//     }

// private:
//     void topicA_callback(const std_msgs::msg::String::SharedPtr msg)
//     {
//         // RCLCPP_INFO(this->get_logger(), "Received message: '%s'", msg->data.c_str());
//         // publisher1_->publish(*msg);
//         // RCLCPP_INFO(this->get_logger(), "Published message: '%s'", msg->data.c_str());
//     }
//     void topicB_callback(const std_msgs::msg::Float32::SharedPtr msg)
//     {
//         // start_hamburg = std::chrono::high_resolution_clock::now();
//         // auto duration = std::chrono::duration_cast<std::chrono::microseconds>(start_hamburg - start_cordoba);

//         // RCLCPP_INFO(this->get_logger(), "Message Reached here at %llu", duration.count());

//                 auto now = this->get_clock()->now();
//         auto now_us = now.nanoseconds() / 1000;

//         RCLCPP_INFO(
//             this->get_logger(),
//             "Current timestamp: %ld us",
//             now_us
//         );


//         publisher1_->publish(*msg);
//     }
//     void topicC_callback(const std_msgs::msg::String::SharedPtr msg)
//     {
//         // RCLCPP_INFO(this->get_logger(), "Received message: '%s'", msg->data.c_str());
//         // publisher1_->publish(*msg);
//         // RCLCPP_INFO(this->get_logger(), "Published message: '%s'", msg->data.c_str());
//     }

//     void topicD_callback(const std_msgs::msg::String::SharedPtr msg)
//     {
//         // RCLCPP_INFO(this->get_logger(), "Received message: '%s'", msg->data.c_str());
//         // publisher1_->publish(*msg);
//         // RCLCPP_INFO(this->get_logger(), "Published message: '%s'", msg->data.c_str());
//     }

//     rclcpp::Publisher<std_msgs::msg::Float32>::SharedPtr publisher1_;
//     rclcpp::Subscription<std_msgs::msg::String>::SharedPtr subscriptionA_;
//     rclcpp::Subscription<std_msgs::msg::Float32>::SharedPtr subscriptionB_;
//     rclcpp::Subscription<std_msgs::msg::String>::SharedPtr subscriptionC_;
//     rclcpp::Subscription<std_msgs::msg::String>::SharedPtr subscriptionD_;
// };



#include <rclcpp/rclcpp.hpp>
#include <std_msgs/msg/byte_multi_array.hpp>
#include <std_msgs/msg/string.hpp>

class hamburg : public rclcpp::Node
{
public:
    hamburg() : Node("hamburg")
    {
        // Publisher (1 MB payload)
        publisher1_ =
            this->create_publisher<std_msgs::msg::ByteMultiArray>("parana", 10);

        // Subscribers
        subscriptionA_ = this->create_subscription<std_msgs::msg::String>(
            "nile", 10,
            std::bind(&hamburg::topicA_callback, this, std::placeholders::_1));

        subscriptionB_ = this->create_subscription<std_msgs::msg::ByteMultiArray>(
            "tigris", 10,
            std::bind(&hamburg::topicB_callback, this, std::placeholders::_1));

        subscriptionC_ = this->create_subscription<std_msgs::msg::String>(
            "ganges", 10,
            std::bind(&hamburg::topicC_callback, this, std::placeholders::_1));

        subscriptionD_ = this->create_subscription<std_msgs::msg::String>(
            "danube", 10,
            std::bind(&hamburg::topicD_callback, this, std::placeholders::_1));
    }

private:
    void topicA_callback(const std_msgs::msg::String::SharedPtr /*msg*/)
    {
        // intentionally left empty
    }

    void topicB_callback(const std_msgs::msg::ByteMultiArray::SharedPtr msg)
    {
        // Timestamp in microseconds
        auto now = this->get_clock()->now();
        auto now_us = now.nanoseconds() / 1000;

        RCLCPP_INFO(
            this->get_logger(),
            "Received 1 MB payload at timestamp: %ld us, size: %zu bytes",
            now_us,
            msg->data.size()
        );

        // Forward the same 1 MB payload
        publisher1_->publish(*msg);
    }

    void topicC_callback(const std_msgs::msg::String::SharedPtr /*msg*/)
    {
        // intentionally left empty
    }

    void topicD_callback(const std_msgs::msg::String::SharedPtr /*msg*/)
    {
        // intentionally left empty
    }

    rclcpp::Publisher<std_msgs::msg::ByteMultiArray>::SharedPtr publisher1_;
    rclcpp::Subscription<std_msgs::msg::String>::SharedPtr subscriptionA_;
    rclcpp::Subscription<std_msgs::msg::ByteMultiArray>::SharedPtr subscriptionB_;
    rclcpp::Subscription<std_msgs::msg::String>::SharedPtr subscriptionC_;
    rclcpp::Subscription<std_msgs::msg::String>::SharedPtr subscriptionD_;
};




class delhi : public rclcpp::Node
{
public:
    delhi() : Node("delhi")
    {
        publisher1_ = this->create_publisher<std_msgs::msg::String>("columbia", 10);

        timer_ = this->create_wall_timer(
            std::chrono::seconds(1),
            std::bind(&delhi::timer_callback, this));
    }

private:
    void timer_callback()
    {
        auto message = std_msgs::msg::String();
        message.data = "Hello, ROS2!";
        // RCLCPP_INFO(this->get_logger(), "Publishing: '%s'", message.data.c_str());
        publisher1_->publish(message);
    }

    rclcpp::Publisher<std_msgs::msg::String>::SharedPtr publisher1_;
    rclcpp::Subscription<std_msgs::msg::String>::SharedPtr subscriptionA_;
    rclcpp::Subscription<std_msgs::msg::String>::SharedPtr subscriptionB_;
    rclcpp::Subscription<std_msgs::msg::String>::SharedPtr subscriptionC_;
    rclcpp::Subscription<std_msgs::msg::String>::SharedPtr subscriptionD_;
    rclcpp::TimerBase::SharedPtr timer_;
};

class taipei : public rclcpp::Node
{
public:
    taipei() : Node("taipei")
    {
        publisher1_ = this->create_publisher<std_msgs::msg::String>("colorado", 10);

        timer_ = this->create_wall_timer(
            std::chrono::seconds(1),
            std::bind(&taipei::timer_callback, this));

        // Subscribers
        subscriptionA_ = this->create_subscription<std_msgs::msg::String>(
            "columbia", 10, std::bind(&taipei::topicA_callback, this, std::placeholders::_1));
    }

private:
    void timer_callback()
    {
        auto message = std_msgs::msg::String();
        message.data = "Hello, ROS2!";
        // RCLCPP_INFO(this->get_logger(), "Publishing: '%s'", message.data.c_str());
        publisher1_->publish(message);
    }

    void topicA_callback(const std_msgs::msg::String::SharedPtr msg)
    {
        // RCLCPP_INFO(this->get_logger(), "Received message: '%s'", msg->data.c_str());
        publisher1_->publish(*msg);
        // RCLCPP_INFO(this->get_logger(), "Published message: '%s'", msg->data.c_str());
    }

    rclcpp::Publisher<std_msgs::msg::String>::SharedPtr publisher1_;
    rclcpp::Subscription<std_msgs::msg::String>::SharedPtr subscriptionA_;
    rclcpp::Subscription<std_msgs::msg::String>::SharedPtr subscriptionB_;
    rclcpp::Subscription<std_msgs::msg::String>::SharedPtr subscriptionC_;
    rclcpp::Subscription<std_msgs::msg::String>::SharedPtr subscriptionD_;
    rclcpp::TimerBase::SharedPtr timer_;
};

// class osaka : public rclcpp::Node
// {
// public:
//     osaka() : Node("osaka")
//     {
//         publisher1_ = this->create_publisher<std_msgs::msg::String>("salween", 10);
//         publisher2_ = this->create_publisher<std_msgs::msg::Float32>("godavari", 10);

//         //  timer_ = this->create_wall_timer(
//         //       std::chrono::seconds(1),
//         //       std::bind(&osaka::timer_callback, this));

//         // Subscribers
//         subscriptionA_ = this->create_subscription<std_msgs::msg::Float32>(
//             "parana", 10, std::bind(&osaka::topicA_callback, this, std::placeholders::_1));
//         subscriptionB_ = this->create_subscription<std_msgs::msg::String>(
//             "colorado", 10, std::bind(&osaka::topicB_callback, this, std::placeholders::_1));
//         subscriptionC_ = this->create_subscription<std_msgs::msg::String>(
//             "columbia", 10, std::bind(&osaka::topicC_callback, this, std::placeholders::_1));
//     }

// private:
//     void timer_callback()
//     {
//         auto message = std_msgs::msg::String();
//         message.data = "Hello, ROS2!";
//         // RCLCPP_INFO(this->get_logger(), "Publishing: '%s'", message.data.c_str());
//         publisher1_->publish(message);
//     }

//     void topicA_callback(const std_msgs::msg::Float32::SharedPtr msg)
//     {
//         // start_osaka = std::chrono::high_resolution_clock::now();
//         // auto duration = std::chrono::duration_cast<std::chrono::microseconds>(start_osaka - start_cordoba);

//         // RCLCPP_INFO(this->get_logger(), "Message Reached here at %llu", duration.count());
        
//                 auto now = this->get_clock()->now();
//         auto now_us = now.nanoseconds() / 1000;

//         RCLCPP_INFO(
//             this->get_logger(),
//             "Current timestamp: %ld us",
//             now_us
//         );

//         publisher2_->publish(*msg);
//     }

//     void topicB_callback(const std_msgs::msg::String::SharedPtr msg) 
//     {
//         // RCLCPP_INFO(this->get_logger(), "Received message: '%s'", msg->data.c_str());
//         publisher1_->publish(*msg);
//         // RCLCPP_INFO(this->get_logger(), "Published message: '%s'", msg->data.c_str());
//     }
//     void topicC_callback(const std_msgs::msg::String::SharedPtr msg) 
//     {
//         // RCLCPP_INFO(this->get_logger(), "Received message: '%s'", msg->data.c_str());
//         publisher1_->publish(*msg);
//         // RCLCPP_INFO(this->get_logger(), "Published message: '%s'", msg->data.c_str());
//     }

//     rclcpp::Publisher<std_msgs::msg::String>::SharedPtr publisher1_;
//     rclcpp::Publisher<std_msgs::msg::Float32>::SharedPtr publisher2_;
//     rclcpp::Subscription<std_msgs::msg::Float32>::SharedPtr subscriptionA_;
//     rclcpp::Subscription<std_msgs::msg::String>::SharedPtr subscriptionB_;
//     rclcpp::Subscription<std_msgs::msg::String>::SharedPtr subscriptionC_;
// };


#include <rclcpp/rclcpp.hpp>
#include <std_msgs/msg/string.hpp>
#include <std_msgs/msg/byte_multi_array.hpp>

class osaka : public rclcpp::Node
{
public:
    osaka() : Node("osaka")
    {
        publisher1_ =
            this->create_publisher<std_msgs::msg::String>("salween", 10);

        publisher2_ =
            this->create_publisher<std_msgs::msg::ByteMultiArray>("godavari", 10);

        // Subscribers
        subscriptionA_ =
            this->create_subscription<std_msgs::msg::ByteMultiArray>(
                "parana", 10,
                std::bind(&osaka::topicA_callback, this, std::placeholders::_1));

        subscriptionB_ =
            this->create_subscription<std_msgs::msg::String>(
                "colorado", 10,
                std::bind(&osaka::topicB_callback, this, std::placeholders::_1));

        subscriptionC_ =
            this->create_subscription<std_msgs::msg::String>(
                "columbia", 10,
                std::bind(&osaka::topicC_callback, this, std::placeholders::_1));
    }

private:
    void topicA_callback(const std_msgs::msg::ByteMultiArray::SharedPtr msg)
    {
        // Timestamp in microseconds
        auto now = this->get_clock()->now();
        auto now_us = now.nanoseconds() / 1000;

        RCLCPP_INFO(
            this->get_logger(),
            "Received payload at timestamp: %ld us, size: %zu bytes",
            now_us,
            msg->data.size()
        );

        // Forward the same 1 MB payload
        publisher2_->publish(*msg);
    }

    void topicB_callback(const std_msgs::msg::String::SharedPtr msg)
    {
        publisher1_->publish(*msg);
    }

    void topicC_callback(const std_msgs::msg::String::SharedPtr msg)
    {
        publisher1_->publish(*msg);
    }

    rclcpp::Publisher<std_msgs::msg::String>::SharedPtr publisher1_;
    rclcpp::Publisher<std_msgs::msg::ByteMultiArray>::SharedPtr publisher2_;
    rclcpp::Subscription<std_msgs::msg::ByteMultiArray>::SharedPtr subscriptionA_;
    rclcpp::Subscription<std_msgs::msg::String>::SharedPtr subscriptionB_;
    rclcpp::Subscription<std_msgs::msg::String>::SharedPtr subscriptionC_;
};



class hebron : public rclcpp::Node
{
public:
    hebron() : Node("hebron")
    {
        publisher_ = this->create_publisher<std_msgs::msg::String>("chenab", 10);
        timer_ = this->create_wall_timer(
            std::chrono::seconds(1),
            std::bind(&hebron::timer_callback, this));
    }

private:
    void timer_callback()
    {
        auto message = std_msgs::msg::String();
        message.data = "Hello, ROS2!";
        // RCLCPP_INFO(this->get_logger(), "Publishing: '%s'", message.data.c_str());
        publisher_->publish(message);
    }

    rclcpp::Publisher<std_msgs::msg::String>::SharedPtr publisher_;
    rclcpp::TimerBase::SharedPtr timer_;
};

class kingston : public rclcpp::Node
{
public:
    kingston() : Node("kingston")
    {
        publisher_ = this->create_publisher<std_msgs::msg::String>("yamuna", 10);
        timer_ = this->create_wall_timer(
            std::chrono::seconds(1),
            std::bind(&kingston::timer_callback, this));
    }

private:
    void timer_callback()
    {
        auto message = std_msgs::msg::String();
        message.data = "Hello, ROS2!";
        // RCLCPP_INFO(this->get_logger(), "Publishing: '%s'", message.data.c_str());
        publisher_->publish(message);
    }

    rclcpp::Publisher<std_msgs::msg::String>::SharedPtr publisher_;
    rclcpp::TimerBase::SharedPtr timer_;
};

// class tripoli : public rclcpp::Node
// {
// public:
//     tripoli() : Node("tripoli")
//     {
//         publisher1_ = this->create_publisher<std_msgs::msg::Float32>("loire", 10);

//         //  timer_ = this->create_wall_timer(
//         //       std::chrono::seconds(1),
//         //       std::bind(&osaka::timer_callback, this));

//         // Subscribers
//         subscriptionA_ = this->create_subscription<std_msgs::msg::String>(
//             "columbia", 10, std::bind(&tripoli::topicA_callback, this, std::placeholders::_1));
//         subscriptionB_ = this->create_subscription<std_msgs::msg::Float32>(
//             "godavari", 10, std::bind(&tripoli::topicB_callback, this, std::placeholders::_1));
//     }

// private:
//     void topicA_callback(const std_msgs::msg::String::SharedPtr msg)
//     {
//         // RCLCPP_INFO(this->get_logger(), "Received message: '%s'", msg->data.c_str());
//         // RCLCPP_INFO(this->get_logger(), "Published message: '%s'", msg->data.c_str());
//     }

//     void topicB_callback(const std_msgs::msg::Float32::SharedPtr msg)
//     {
//         // start_tripoli = std::chrono::high_resolution_clock::now();
//         // auto duration = std::chrono::duration_cast<std::chrono::microseconds>(start_tripoli - start_cordoba);

//         // RCLCPP_INFO(this->get_logger(), "Message Reached here at %llu", duration.count());
       
//                 auto now = this->get_clock()->now();
//         auto now_us = now.nanoseconds() / 1000;

//         RCLCPP_INFO(
//             this->get_logger(),
//             "Current timestamp: %ld us",
//             now_us
//         );

       
//         publisher1_->publish(*msg);

//     }

//     rclcpp::Publisher<std_msgs::msg::Float32>::SharedPtr publisher1_;

//     rclcpp::Subscription<std_msgs::msg::String>::SharedPtr subscriptionA_;
//     rclcpp::Subscription<std_msgs::msg::Float32>::SharedPtr subscriptionB_;
// };


#include <rclcpp/rclcpp.hpp>
#include <std_msgs/msg/string.hpp>
#include <std_msgs/msg/byte_multi_array.hpp>

class tripoli : public rclcpp::Node
{
public:
    tripoli() : Node("tripoli")
    {
        publisher1_ =
            this->create_publisher<std_msgs::msg::ByteMultiArray>("loire", 10);

        // Subscribers
        subscriptionA_ =
            this->create_subscription<std_msgs::msg::String>(
                "columbia", 10,
                std::bind(&tripoli::topicA_callback, this, std::placeholders::_1));

        subscriptionB_ =
            this->create_subscription<std_msgs::msg::ByteMultiArray>(
                "godavari", 10,
                std::bind(&tripoli::topicB_callback, this, std::placeholders::_1));
    }

private:
    void topicA_callback(const std_msgs::msg::String::SharedPtr /*msg*/)
    {
        // intentionally empty
    }

    void topicB_callback(const std_msgs::msg::ByteMultiArray::SharedPtr msg)
    {
        // Current timestamp in microseconds
        auto now = this->get_clock()->now();
        auto now_us = now.nanoseconds() / 1000;

        RCLCPP_INFO(
            this->get_logger(),
            "Received payload at timestamp: %ld us, size: %zu bytes",
            now_us,
            msg->data.size()
        );

        // Forward the same 1 MB payload
        publisher1_->publish(*msg);
    }

    rclcpp::Publisher<std_msgs::msg::ByteMultiArray>::SharedPtr publisher1_;
    rclcpp::Subscription<std_msgs::msg::String>::SharedPtr subscriptionA_;
    rclcpp::Subscription<std_msgs::msg::ByteMultiArray>::SharedPtr subscriptionB_;
};



// class geneva : public rclcpp::Node
// {
// public:
//     geneva() : Node("geneva")
//     {
//         publisher1_ = this->create_publisher<std_msgs::msg::String>("arkansas", 10);

//         timer_ = this->create_wall_timer(
//             std::chrono::seconds(1),
//             std::bind(&geneva::timer_callback, this));

//         // Subscribers
//         subscriptionA_ = this->create_subscription<std_msgs::msg::Float32>(
//             "parana", 10, std::bind(&geneva::topicA_callback, this, std::placeholders::_1));
//         subscriptionB_ = this->create_subscription<std_msgs::msg::String>(
//             "danube", 10, std::bind(&geneva::topicB_callback, this, std::placeholders::_1));
//         subscriptionC_ = this->create_subscription<std_msgs::msg::String>(
//             "tagus", 10, std::bind(&geneva::topicC_callback, this, std::placeholders::_1));

//         subscriptionD_ = this->create_subscription<std_msgs::msg::String>(
//             "congo", 10, std::bind(&geneva::topicD_callback, this, std::placeholders::_1));
//     }

// private:
//     void timer_callback()
//     {
//         auto message = std_msgs::msg::String();
//         message.data = "Hello, ROS2!";
//         // RCLCPP_INFO(this->get_logger(), "Publishing: '%s'", message.data.c_str());
//         publisher1_->publish(message);
//     }

//     void topicA_callback(const std_msgs::msg::Float32::SharedPtr msg)
//     {
//     }

//     void topicB_callback(const std_msgs::msg::String::SharedPtr msg)
//     {
//         // //RCLCPP_INFO(this->get_logger(), "Received message: '%s'", msg->data.c_str());
//         publisher1_->publish(*msg);
//         // //RCLCPP_INFO(this->get_logger(), "Published message: '%s'", msg->data.c_str());
//     }

//     void topicC_callback(const std_msgs::msg::String::SharedPtr msg)
//     {
//         // //RCLCPP_INFO(this->get_logger(), "Received message: '%s'", msg->data.c_str());
//         publisher1_->publish(*msg);
//         // //RCLCPP_INFO(this->get_logger(), "Published message: '%s'", msg->data.c_str());
//     }

//     void topicD_callback(const std_msgs::msg::String::SharedPtr msg)
//     {
//         // //RCLCPP_INFO(this->get_logger(), "Received message: '%s'", msg->data.c_str());
//         publisher1_->publish(*msg);
//         // //RCLCPP_INFO(this->get_logger(), "Published message: '%s'", msg->data.c_str());
//     }

//     void topicE_callback(const std_msgs::msg::String::SharedPtr msg)
//     {
//         // //RCLCPP_INFO(this->get_logger(), "Received message: '%s'", msg->data.c_str());
//         publisher1_->publish(*msg);
//         // //RCLCPP_INFO(this->get_logger(), "Published message: '%s'", msg->data.c_str());
//     }

//     void topicF_callback(const std_msgs::msg::String::SharedPtr msg)
//     {
//         // //RCLCPP_INFO(this->get_logger(), "Received message: '%s'", msg->data.c_str());
//         publisher1_->publish(*msg);
//         // //RCLCPP_INFO(this->get_logger(), "Published message: '%s'", msg->data.c_str());
//     }

//     rclcpp::Publisher<std_msgs::msg::String>::SharedPtr publisher1_;

//     rclcpp::Subscription<std_msgs::msg::Float32>::SharedPtr subscriptionA_;
//     rclcpp::Subscription<std_msgs::msg::String>::SharedPtr subscriptionB_;
//     rclcpp::Subscription<std_msgs::msg::String>::SharedPtr subscriptionC_;
//     rclcpp::Subscription<std_msgs::msg::String>::SharedPtr subscriptionD_;

//     rclcpp::TimerBase::SharedPtr timer_;
// };


#include <rclcpp/rclcpp.hpp>
#include <std_msgs/msg/string.hpp>
#include <std_msgs/msg/byte_multi_array.hpp>

class geneva : public rclcpp::Node
{
public:
    geneva() : Node("geneva")
    {
        publisher1_ =
            this->create_publisher<std_msgs::msg::String>("arkansas", 10);

        timer_ = this->create_wall_timer(
            std::chrono::seconds(1),
            std::bind(&geneva::timer_callback, this));

        // Subscribers
        subscriptionA_ =
            this->create_subscription<std_msgs::msg::ByteMultiArray>(
                "parana", 10,
                std::bind(&geneva::topicA_callback, this, std::placeholders::_1));

        subscriptionB_ =
            this->create_subscription<std_msgs::msg::String>(
                "danube", 10,
                std::bind(&geneva::topicB_callback, this, std::placeholders::_1));

        subscriptionC_ =
            this->create_subscription<std_msgs::msg::String>(
                "tagus", 10,
                std::bind(&geneva::topicC_callback, this, std::placeholders::_1));

        subscriptionD_ =
            this->create_subscription<std_msgs::msg::String>(
                "congo", 10,
                std::bind(&geneva::topicD_callback, this, std::placeholders::_1));
    }

private:
    void timer_callback()
    {
        std_msgs::msg::String message;
        message.data = "Hello, ROS2!";
        publisher1_->publish(message);
    }

    void topicA_callback(const std_msgs::msg::ByteMultiArray::SharedPtr msg)
    {
        RCLCPP_DEBUG(
            this->get_logger(),
            "Received payload on parana, size: %zu bytes",
            msg->data.size()
        );
    }

    void topicB_callback(const std_msgs::msg::String::SharedPtr msg)
    {
        publisher1_->publish(*msg);
    }

    void topicC_callback(const std_msgs::msg::String::SharedPtr msg)
    {
        publisher1_->publish(*msg);
    }

    void topicD_callback(const std_msgs::msg::String::SharedPtr msg)
    {
        publisher1_->publish(*msg);
    }

    rclcpp::Publisher<std_msgs::msg::String>::SharedPtr publisher1_;
    rclcpp::Subscription<std_msgs::msg::ByteMultiArray>::SharedPtr subscriptionA_;
    rclcpp::Subscription<std_msgs::msg::String>::SharedPtr subscriptionB_;
    rclcpp::Subscription<std_msgs::msg::String>::SharedPtr subscriptionC_;
    rclcpp::Subscription<std_msgs::msg::String>::SharedPtr subscriptionD_;
    rclcpp::TimerBase::SharedPtr timer_;
};


class monaco : public rclcpp::Node
{
public:
    monaco() : Node("monaco")
    {
        publisher1_ = this->create_publisher<std_msgs::msg::String>("ohio", 10);

        timer_ = this->create_wall_timer(
            std::chrono::seconds(1),
            std::bind(&monaco::timer_callback, this));

        // Subscribers
        subscriptionA_ = this->create_subscription<std_msgs::msg::String>(
            "congo", 10, std::bind(&monaco::topicA_callback, this, std::placeholders::_1));
    }

private:
    void timer_callback()
    {
        auto message = std_msgs::msg::String();
        message.data = "Hello, ROS2!";
        // RCLCPP_INFO(this->get_logger(), "Publishing: '%s'", message.data.c_str());
        publisher1_->publish(message);
    }

    void topicA_callback(const std_msgs::msg::String::SharedPtr msg)
    {
        // RCLCPP_INFO(this->get_logger(), "Received message: '%s'", msg->data.c_str());
        publisher1_->publish(*msg);
        // RCLCPP_INFO(this->get_logger(), "Published message: '%s'", msg->data.c_str());
    }

    void topicB_callback(const std_msgs::msg::String::SharedPtr msg)
    {
        // RCLCPP_INFO(this->get_logger(), "Received message: '%s'", msg->data.c_str());
        // RCLCPP_INFO(this->get_logger(), "Published message: '%s'", msg->data.c_str());
    }

    void topicC_callback(const std_msgs::msg::String::SharedPtr msg)
    {
        // RCLCPP_INFO(this->get_logger(), "Received message: '%s'", msg->data.c_str());
        // RCLCPP_INFO(this->get_logger(), "Published message: '%s'", msg->data.c_str());
    }

    void topicD_callback(const std_msgs::msg::String::SharedPtr msg)
    {
        // RCLCPP_INFO(this->get_logger(), "Received message: '%s'", msg->data.c_str());
        // RCLCPP_INFO(this->get_logger(), "Published message: '%s'", msg->data.c_str());
    }

    void topicE_callback(const std_msgs::msg::String::SharedPtr msg)
    {
        // RCLCPP_INFO(this->get_logger(), "Received message: '%s'", msg->data.c_str());
        // RCLCPP_INFO(this->get_logger(), "Published message: '%s'", msg->data.c_str());
    }

    void topicF_callback(const std_msgs::msg::String::SharedPtr msg) 
    {
        // RCLCPP_INFO(this->get_logger(), "Received message: '%s'", msg->data.c_str());

        // RCLCPP_INFO(this->get_logger(), "Published message: '%s'", msg->data.c_str());
    }

    rclcpp::Publisher<std_msgs::msg::String>::SharedPtr publisher1_;

    rclcpp::Subscription<std_msgs::msg::String>::SharedPtr subscriptionA_;
    rclcpp::Subscription<std_msgs::msg::String>::SharedPtr subscriptionB_;
    rclcpp::Subscription<std_msgs::msg::String>::SharedPtr subscriptionC_;
    rclcpp::Subscription<std_msgs::msg::String>::SharedPtr subscriptionD_;

    rclcpp::TimerBase::SharedPtr timer_;
};


#include <rclcpp/rclcpp.hpp>
#include <std_msgs/msg/string.hpp>
#include <std_msgs/msg/byte_multi_array.hpp>

class rotterdam : public rclcpp::Node
{
public:
    rotterdam() : Node("rotterdam")
    {
        publisher1_ =
            this->create_publisher<std_msgs::msg::String>("murray", 10);

        timer_ = this->create_wall_timer(
            std::chrono::seconds(1),
            std::bind(&rotterdam::timer_callback, this));

        // Subscriber (1 MB payload)
        subscriptionA_ =
            this->create_subscription<std_msgs::msg::ByteMultiArray>(
                "mekong", 10,
                std::bind(&rotterdam::topicA_callback, this, std::placeholders::_1));
    }

private:
    void timer_callback()
    {
        std_msgs::msg::String message;
        message.data = "Hello, ROS2!";
        publisher1_->publish(message);
    }

    void topicA_callback(const std_msgs::msg::ByteMultiArray::SharedPtr msg)
    {
        RCLCPP_DEBUG(
            this->get_logger(),
            "Received payload on mekong, size: %zu bytes",
            msg->data.size()
        );

        // Publish string response (unchanged behavior)
        std_msgs::msg::String message;
        message.data = "Hello, ROS2!";
        publisher1_->publish(message);
    }

    rclcpp::Publisher<std_msgs::msg::String>::SharedPtr publisher1_;
    rclcpp::Subscription<std_msgs::msg::ByteMultiArray>::SharedPtr subscriptionA_;
    rclcpp::TimerBase::SharedPtr timer_;
};


#include <rclcpp/rclcpp.hpp>
#include <std_msgs/msg/byte_multi_array.hpp>

class barcelona : public rclcpp::Node
{
public:
    barcelona() : Node("barcelona")
    {
        publisher1_ =
            this->create_publisher<std_msgs::msg::ByteMultiArray>("lena", 10);

        // Subscriber
        subscriptionA_ =
            this->create_subscription<std_msgs::msg::ByteMultiArray>(
                "mekong", 10,
                std::bind(&barcelona::topicA_callback, this, std::placeholders::_1));
    }

private:
    void topicA_callback(const std_msgs::msg::ByteMultiArray::SharedPtr msg)
    {
        auto now = this->get_clock()->now();
        auto now_us = now.nanoseconds() / 1000;

        RCLCPP_INFO(
            this->get_logger(),
            "Received payload at timestamp: %ld us, size: %zu bytes",
            now_us,
            msg->data.size()
        );

        // Forward the same 1 MB payload
        publisher1_->publish(*msg);
    }

    rclcpp::Publisher<std_msgs::msg::ByteMultiArray>::SharedPtr publisher1_;
    rclcpp::Subscription<std_msgs::msg::ByteMultiArray>::SharedPtr subscriptionA_;
};


class arequipa : public rclcpp::Node
{
public:
    arequipa() : Node("arequipa")
    {

        // Subscribers
        subscriptionA_ = this->create_subscription<std_msgs::msg::String>(
            "arkansas", 10, std::bind(&arequipa::topicA_callback, this, std::placeholders::_1));
    }

private:
    void topicA_callback(const std_msgs::msg::String::SharedPtr msg)
    {
        // RCLCPP_INFO(this->get_logger(), "Received message: '%s'", msg->data.c_str());
        // RCLCPP_INFO(this->get_logger(), "Published message: '%s'", msg->data.c_str());
    }

    rclcpp::Publisher<std_msgs::msg::String>::SharedPtr publisher1_;

    rclcpp::Subscription<std_msgs::msg::String>::SharedPtr subscriptionA_;
    rclcpp::Subscription<std_msgs::msg::String>::SharedPtr subscriptionB_;
};


#include <rclcpp/rclcpp.hpp>
#include <std_msgs/msg/string.hpp>
#include <std_msgs/msg/byte_multi_array.hpp>

class mandalay : public rclcpp::Node
{
public:
    mandalay() : Node("mandalay")
    {
        publisher1_ =
            this->create_publisher<std_msgs::msg::String>("tagus", 10);

        publisher2_ =
            this->create_publisher<std_msgs::msg::ByteMultiArray>("brazos", 10);

        publisher3_ =
            this->create_publisher<std_msgs::msg::String>("missouri", 10);

        timer_ = this->create_wall_timer(
            std::chrono::seconds(1),
            std::bind(&mandalay::timer_callback, this));

        // Subscribers
        subscriptionA_ =
            this->create_subscription<std_msgs::msg::String>(
                "danube", 10,
                std::bind(&mandalay::topicA_callback, this, std::placeholders::_1));

        subscriptionB_ =
            this->create_subscription<std_msgs::msg::String>(
                "chenab", 10,
                std::bind(&mandalay::topicB_callback, this, std::placeholders::_1));

        subscriptionC_ =
            this->create_subscription<std_msgs::msg::String>(
                "salween", 10,
                std::bind(&mandalay::topicC_callback, this, std::placeholders::_1));

        subscriptionE_ =
            this->create_subscription<std_msgs::msg::String>(
                "yamuna", 10,
                std::bind(&mandalay::topicE_callback, this, std::placeholders::_1));

        subscriptionF_ =
            this->create_subscription<std_msgs::msg::ByteMultiArray>(
                "loire", 10,
                std::bind(&mandalay::topicF_callback, this, std::placeholders::_1));
    }

private:
    void timer_callback()
    {
        std_msgs::msg::String message;
        message.data = "Hello, ROS2!";
        publisher1_->publish(message);
        publisher3_->publish(message);
    }

    void topicA_callback(const std_msgs::msg::String::SharedPtr msg)
    {
        publisher1_->publish(*msg);
        publisher3_->publish(*msg);
    }

    void topicB_callback(const std_msgs::msg::String::SharedPtr msg)
    {
        publisher1_->publish(*msg);
        publisher3_->publish(*msg);
    }

    void topicC_callback(const std_msgs::msg::String::SharedPtr msg)
    {
        publisher1_->publish(*msg);
        publisher3_->publish(*msg);
    }

    void topicE_callback(const std_msgs::msg::String::SharedPtr msg)
    {
        publisher1_->publish(*msg);
        publisher3_->publish(*msg);
    }

    void topicF_callback(const std_msgs::msg::ByteMultiArray::SharedPtr msg)
    {
        // Timestamp in microseconds
        auto now = this->get_clock()->now();
        auto now_us = now.nanoseconds() / 1000;

        RCLCPP_INFO(
            this->get_logger(),
            "Received payload at timestamp: %ld us, size: %zu bytes",
            now_us,
            msg->data.size()
        );

        // Forward the same 1 MB payload
        publisher2_->publish(*msg);
    }

    rclcpp::Publisher<std_msgs::msg::String>::SharedPtr publisher1_;
    rclcpp::Publisher<std_msgs::msg::ByteMultiArray>::SharedPtr publisher2_;
    rclcpp::Publisher<std_msgs::msg::String>::SharedPtr publisher3_;

    rclcpp::Subscription<std_msgs::msg::String>::SharedPtr subscriptionA_;
    rclcpp::Subscription<std_msgs::msg::String>::SharedPtr subscriptionB_;
    rclcpp::Subscription<std_msgs::msg::String>::SharedPtr subscriptionC_;
    rclcpp::Subscription<std_msgs::msg::String>::SharedPtr subscriptionE_;
    rclcpp::Subscription<std_msgs::msg::ByteMultiArray>::SharedPtr subscriptionF_;

    rclcpp::TimerBase::SharedPtr timer_;
};


#include <rclcpp/rclcpp.hpp>
#include <std_msgs/msg/string.hpp>
#include <std_msgs/msg/byte_multi_array.hpp>

class ponce : public rclcpp::Node
{
public:
    ponce() : Node("ponce")
    {
        publisher1_ =
            this->create_publisher<std_msgs::msg::String>("congo", 10);

        publisher2_ =
            this->create_publisher<std_msgs::msg::ByteMultiArray>("mekong", 10);

        timer_ = this->create_wall_timer(
            std::chrono::seconds(1),
            std::bind(&ponce::timer_callback, this));

        // Subscribers
        subscriptionA_ =
            this->create_subscription<std_msgs::msg::String>(
                "tagus", 10,
                std::bind(&ponce::topicA_callback, this, std::placeholders::_1));

        subscriptionB_ =
            this->create_subscription<std_msgs::msg::String>(
                "danube", 10,
                std::bind(&ponce::topicB_callback, this, std::placeholders::_1));

        subscriptionC_ =
            this->create_subscription<std_msgs::msg::String>(
                "missouri", 10,
                std::bind(&ponce::topicC_callback, this, std::placeholders::_1));

        subscriptionE_ =
            this->create_subscription<std_msgs::msg::ByteMultiArray>(
                "brazos", 10,
                std::bind(&ponce::topicE_callback, this, std::placeholders::_1));

        subscriptionF_ =
            this->create_subscription<std_msgs::msg::String>(
                "yamuna", 10,
                std::bind(&ponce::topicF_callback, this, std::placeholders::_1));
    }

private:
    void timer_callback()
    {
        std_msgs::msg::String message;
        message.data = "Hello, ROS2!";
        publisher1_->publish(message);
    }

    void topicA_callback(const std_msgs::msg::String::SharedPtr msg)
    {
        publisher1_->publish(*msg);
    }

    void topicB_callback(const std_msgs::msg::String::SharedPtr msg)
    {
        publisher1_->publish(*msg);
    }

    void topicC_callback(const std_msgs::msg::String::SharedPtr msg)
    {
        publisher1_->publish(*msg);
    }

    void topicE_callback(const std_msgs::msg::ByteMultiArray::SharedPtr msg)
    {
        // Timestamp in microseconds
        auto now = this->get_clock()->now();
        auto now_us = now.nanoseconds() / 1000;

        RCLCPP_INFO(
            this->get_logger(),
            "Received payload at timestamp: %ld us, size: %zu bytes",
            now_us,
            msg->data.size()
        );

        // Forward the same 1 MB payload
        publisher2_->publish(*msg);
    }

    void topicF_callback(const std_msgs::msg::String::SharedPtr msg)
    {
        publisher1_->publish(*msg);
    }

    rclcpp::Publisher<std_msgs::msg::String>::SharedPtr publisher1_;
    rclcpp::Publisher<std_msgs::msg::ByteMultiArray>::SharedPtr publisher2_;

    rclcpp::Subscription<std_msgs::msg::String>::SharedPtr subscriptionA_;
    rclcpp::Subscription<std_msgs::msg::String>::SharedPtr subscriptionB_;
    rclcpp::Subscription<std_msgs::msg::String>::SharedPtr subscriptionC_;
    rclcpp::Subscription<std_msgs::msg::ByteMultiArray>::SharedPtr subscriptionE_;
    rclcpp::Subscription<std_msgs::msg::String>::SharedPtr subscriptionF_;

    rclcpp::TimerBase::SharedPtr timer_;
};


// class georgetown : public rclcpp::Node
// {
// public:
//     georgetown() : Node("georgetown")
//     {

//         // Subscribers
//         subscriptionB_ = this->create_subscription<std_msgs::msg::String>(
//             "murray", 10, std::bind(&georgetown::topicB_callback, this, std::placeholders::_1));
//         subscriptionA_ = this->create_subscription<std_msgs::msg::Float32>(
//             "lena", 10, std::bind(&georgetown::topicA_callback, this, std::placeholders::_1));
//     }

// private:
//     void topicA_callback(const std_msgs::msg::Float32::SharedPtr msg)
//     {
//         // start_georgetown = std::chrono::high_resolution_clock::now();
//         // auto duration = std::chrono::duration_cast<std::chrono::microseconds>(start_georgetown - start_cordoba);

//         // RCLCPP_INFO(this->get_logger(), "Message Reached here at %llu", duration.count());
 
//                 auto now = this->get_clock()->now();
//         auto now_us = now.nanoseconds() / 1000;

//         RCLCPP_INFO(
//             this->get_logger(),
//             "Current timestamp: %ld us",
//             now_us
//         );

 
//     }

//     void topicB_callback(const std_msgs::msg::String::SharedPtr msg)
//     {
//         // RCLCPP_INFO(this->get_logger(), "Received message: '%s'", msg->data.c_str());
//         // RCLCPP_INFO(this->get_logger(), "Published message: '%s'", msg->data.c_str());
//     }

//     rclcpp::Subscription<std_msgs::msg::Float32>::SharedPtr subscriptionA_;
//     rclcpp::Subscription<std_msgs::msg::String>::SharedPtr subscriptionB_;
//     rclcpp::Subscription<std_msgs::msg::String>::SharedPtr subscriptionC_;
//     rclcpp::Subscription<std_msgs::msg::String>::SharedPtr subscriptionD_;

//     rclcpp::TimerBase::SharedPtr timer_;
// };


#include <rclcpp/rclcpp.hpp>
#include <std_msgs/msg/string.hpp>
#include <std_msgs/msg/byte_multi_array.hpp>

class georgetown : public rclcpp::Node
{
public:
    georgetown() : Node("georgetown")
    {
        // Subscribers
        subscriptionB_ =
            this->create_subscription<std_msgs::msg::String>(
                "murray", 10,
                std::bind(&georgetown::topicB_callback, this, std::placeholders::_1));

        subscriptionA_ =
            this->create_subscription<std_msgs::msg::ByteMultiArray>(
                "lena", 10,
                std::bind(&georgetown::topicA_callback, this, std::placeholders::_1));
    }

private:
    void topicA_callback(const std_msgs::msg::ByteMultiArray::SharedPtr msg)
    {
        // Timestamp in microseconds
        auto now = this->get_clock()->now();
        auto now_us = now.nanoseconds() / 1000;

        RCLCPP_INFO(
            this->get_logger(),
            "Received payload at timestamp: %ld us, size: %zu bytes",
            now_us,
            msg->data.size()
        );
    }

    void topicB_callback(const std_msgs::msg::String::SharedPtr /*msg*/)
    {
        // intentionally empty
    }

    rclcpp::Subscription<std_msgs::msg::ByteMultiArray>::SharedPtr subscriptionA_;
    rclcpp::Subscription<std_msgs::msg::String>::SharedPtr subscriptionB_;
};


extern "C" {
__attribute__((weak))
void protect_trusted_libraries_with_pkey(void);
}

int main(int argc, char **argv)
{
    // if (argc < 2)
    // {
    //     std::cerr << "Usage: ./app <start_time_in_ns>" << std::endl;
    //     return 1;
    // }

    // // Convert the argument to a long long (nanoseconds)
    // long long start_time_ns = std::atoll(argv[1]);

    // // Get the current time at the start of main()
    // auto main_time = std::chrono::high_resolution_clock::now();
    // auto main_time_ns = std::chrono::time_point_cast<std::chrono::nanoseconds>(main_time).time_since_epoch().count();

    // // Calculate the difference ks'
    // long long duration_ns = main_time_ns - start_time_ns;

    // std::cout << "Time elapsed from execve to main(): " << duration_ns << " nanoseconds" << std::endl;
  //   protect_trusted_libraries_with_pkey();
    putenv("MY_VAR=hello");

    rclcpp::init(argc, argv);

    // Create a vector to hold all the node instances
    std::vector<std::shared_ptr<rclcpp::Node>> nodes;

    // Add instances of each node to the vector
    nodes.push_back(std::make_shared<cordoba>());
     nodes.push_back(std::make_shared<freeport>());
     nodes.push_back(std::make_shared<medellin>());
     nodes.push_back(std::make_shared<portsmouth>());
    nodes.push_back(std::make_shared<lyon>());
     nodes.push_back(std::make_shared<hamburg>());
     nodes.push_back(std::make_shared<delhi>());
     nodes.push_back(std::make_shared<taipei>());
     nodes.push_back(std::make_shared<osaka>());
     nodes.push_back(std::make_shared<tripoli>());
     nodes.push_back(std::make_shared<kingston>());
     nodes.push_back(std::make_shared<hebron>());
     nodes.push_back(std::make_shared<mandalay>());
     nodes.push_back(std::make_shared<ponce>());
     nodes.push_back(std::make_shared<barcelona>());
     nodes.push_back(std::make_shared<monaco>());
     nodes.push_back(std::make_shared<georgetown>());
     nodes.push_back(std::make_shared<rotterdam>());
     nodes.push_back(std::make_shared<geneva>());
     nodes.push_back(std::make_shared<arequipa>());

    // Create an executor
 //   rclcpp::executors::SingleThreadedExecutor executor;
rclcpp::executors::MultiThreadedExecutor executor;
    // Add each node to the executor
    for (auto &node : nodes)
    {
        executor.add_node(node);
    }
    printf("hello\n");

    // Spin the executor
    executor.spin();

    // Shutdown ROS
    rclcpp::shutdown();
    return 0;
}
