package googlepubsub

import (
	"context"
	"encoding/json"
	"fmt"

	"cloud.google.com/go/pubsub"
	"github.com/golgeek/sb/internal/models"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
)

type ReplicationQueuePubSub struct {
	project        string
	topicName      string
	subscriberName string
	client         *pubsub.Client
	topic          *pubsub.Topic
	subscription   *pubsub.Subscription
}

func NewReplicationQueuePubSub(options *viper.Viper, hostname string) (rq *ReplicationQueuePubSub, err error) {

	// We get the topic name and the subscriber name
	project := options.GetString("project")
	topicName := options.GetString("topic-name")
	subscriberName := fmt.Sprintf("%s-%s", topicName, hostname)

	// We init a client
	client, err := pubsub.NewClient(context.Background(), project)
	if err != nil {
		return
	}

	rq = &ReplicationQueuePubSub{
		project:        project,
		topicName:      topicName,
		subscriberName: subscriberName,
		client:         client,
	}

	// Get the topic where to push (and create if it doesn't exist yet)
	rq.topic, err = rq.getTopic(true)
	if err != nil {
		return
	}

	rq.subscription, err = rq.getSubscription(true)
	if err != nil {
		return
	}

	return

}

func (rq *ReplicationQueuePubSub) PushToQueue(entry *models.Replication) (err error) {

	ctx := context.Background()

	if rq.topic == nil {
		return fmt.Errorf("replication queue Google PubSub not initialized")
	}

	entryStr, err := json.Marshal(entry)
	if err != nil {
		return errors.Wrap(err, "unable to json.Marshal entry")
	}

	_, err = rq.topic.Publish(ctx, &pubsub.Message{Data: entryStr}).Get(ctx)
	if err != nil {
		return errors.Wrap(err, "unable to publish entry to Google PubSub")
	}

	return
}

func (rq *ReplicationQueuePubSub) ConsumeQueue(callbackFn func(entry *models.Replication) error) (err error) {

	return rq.subscription.Receive(context.Background(), func(ctx context.Context, msg *pubsub.Message) {

		entry := models.Replication{}

		// Unmarshal the event
		err = json.Unmarshal(msg.Data, &entry)
		if err != nil {
			return
		}

		// Call the callback function
		err = callbackFn(&entry)
		if err != nil {
			return
		}

		// Let's acknowledge the message
		msg.Ack()
	})

}

func (rq *ReplicationQueuePubSub) getTopic(createIfNotExists bool) (topic *pubsub.Topic, err error) {

	ctx := context.Background()

	topic = rq.client.Topic(rq.topicName)
	exists, err := topic.Exists(ctx)
	if err != nil {
		err = errors.Wrap(err, "unable to check if Google PubSub topic exists")
		return
	}

	if !exists {
		if !createIfNotExists {
			err = fmt.Errorf("this Google PubSub topic does not exist")
			return
		}

		topic, err = rq.client.CreateTopic(ctx, rq.topicName)
		if err != nil {
			err = errors.Wrap(err, "unable to create Google PubSub topic")
			return
		}
	}

	return
}

func (rq *ReplicationQueuePubSub) getSubscription(createIfNotExists bool) (subscription *pubsub.Subscription, err error) {

	ctx := context.Background()

	subscription = rq.client.Subscription(rq.subscriberName)

	exists, err := subscription.Exists(ctx)
	if err != nil {
		err = errors.Wrap(err, "unable to check if Google PubSub subscription exists")
		return
	}
	if !exists {

		if !createIfNotExists {
			err = fmt.Errorf("this Google PubSub subscription does not exist")
			return
		}

		subscription, err = rq.client.CreateSubscription(ctx, rq.subscriberName, pubsub.SubscriptionConfig{
			Topic:                 rq.topic,
			EnableMessageOrdering: true,
		})
		if err != nil {
			err = errors.Wrap(err, "unable to create Google PubSub subscription")
			return
		}
	}
	return
}
